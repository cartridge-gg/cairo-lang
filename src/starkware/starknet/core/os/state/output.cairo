from starkware.cairo.common.dict import DictAccess
from starkware.cairo.common.math import assert_nn_le
from starkware.cairo.common.math_cmp import is_not_zero
from starkware.starknet.core.os.state.commitment import StateEntry
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.serialize import serialize_word
from starkware.cairo.common.log2_ceil import log2_ceil
from starkware.cairo.common.pow import pow
from starkware.cairo.common.cairo_builtins import PoseidonBuiltin
from starkware.cairo.common.math_cmp import is_le_felt
from starkware.cairo.common.builtin_poseidon.poseidon import poseidon_hash_many

// from starkware.starknet.core.os.output import Crdt
// The on-chain data for contract state changes has the following format:
//
// * The number of affected contracts.
// * For each contract:
//   * Header:
//     * The contract address (1 word).
//     * 1 word with the following info:
//       * A flag indicating whether the class hash was updated,
//       * A flag indicating whether the number of updates is small (< 256),
//       * the number of entry updates (packed according to the previous flag),
//       * the new nonce (if `full_output` is used or if it was updated),
//       * the old nonce (if `full_output` is used),
//          +-------------+----------------+------------+ LSB
//          | n_updates   | n_updates_flag | class_flag |
//          | 8 or 64 bit | 1 bit          | 1 bit      |
//          +-------------+----------------+------------+
//         OR (if the nonce was updated)
//          +-----------+-------------+----------------+------------+ LSB
//          | new_nonce | n_updates   | n_updates_flag | class_flag |
//          | 64 bits   | 8 or 64 bit | 1 bit          | 1 bit      |
//          +-----------+-------------+----------------+------------+
//         OR (if `full_output` is used)
//          +-----------+-----------+-------------+----------------+------------+ LSB
//          | old_nonce | new_nonce | n_updates   | n_updates_flag | class_flag |
//          | 64 bits   | 64 bits   | 8 or 64 bit | 1 bit          | 1 bit      |
//          +-----------+-----------+-------------+----------------+------------+
//
//   * The old class hash for this contract (1 word, if `full_output` is used).
//   * The new class hash for this contract (1 word, if it was updated or `full_output` is used).
//   * For each entry update:
//       * key (1 word).
//       * old value (1 word, only when `full_output` is used).
//       * new value (1 word).
//
// The on-chain data for contract class changes has the following format:
// * The number of classes that have been declared.
// * For each contract class:
//   * The class hash (1 word).
//   * The old compiled class hash (1 word, only when `full_output` is used).
//   * The compiled class hash (casm, 1 word).

// A bound on the number of contract state entry updates in a contract.
const N_UPDATES_BOUND = 2 ** 64;
// Number of updates that is lower than this bound will be packed more efficiently in the header.
const N_UPDATES_SMALL_PACKING_BOUND = 2 ** 8;
// A bound on the nonce of a contract.
const NONCE_BOUND = 2 ** 64;

// Represents an update of a state entry; Either a contract state entry of a contract or a
// contract class entry in the contract class hash mapping.
struct StateUpdateEntry {
    // The entry's key.
    key: felt,
    // The new value.
    value: felt,
}

struct FullStateUpdateEntry {
    // The entry's key.
    key: felt,
    // The previous value.
    prev_value: felt,
    // The new value.
    new_value: felt,
}

struct Crdt {
    address: felt,
    slot_len: felt,
    slots: Slot*,
}
struct Slot{ 
    key: felt,
    crdt_type: felt,
}
// Outputs the entries that were changed in `update_ptr` into `state_updates_ptr`.
// Returns the number of such entries.
func serialize_da_changes{state_updates_ptr: felt*, range_check_ptr, poseidon_ptr: PoseidonBuiltin*}(
    update_ptr: DictAccess*, n_updates: felt, full_output: felt,
    ptr_to_storage_keys: Slot*, array_len: felt
) -> (felt, felt) {
    alloc_locals;
    if (full_output == 0) {
        // Keep a pointer to the start of the array.
        let state_updates_start = state_updates_ptr;
        // Cast `state_updates_ptr` to `StateUpdateEntry*`.
        let state_updates = cast(state_updates_ptr, StateUpdateEntry*);
        
        serialize_da_changes_inner{state_updates=state_updates}(
            update_ptr=update_ptr, n_updates=n_updates, ptr_to_storage_keys=ptr_to_storage_keys, array_len=array_len
        );
        // Cast back to `felt*`.
        let state_updates_ptr = cast(state_updates, felt*);
        return ((state_updates_ptr - state_updates_start) / StateUpdateEntry.SIZE,1);
    } else {
        // Keep a pointer to the start of the array.
        let state_updates_start = state_updates_ptr;
        // Cast `state_updates_ptr` to `FullStateUpdateEntry*`.
        let state_updates_full = cast(state_updates_ptr, FullStateUpdateEntry*);

        serialize_da_changes_inner_full{state_updates=state_updates_full}(
            update_ptr=update_ptr, n_updates=n_updates, ptr_to_storage_keys=ptr_to_storage_keys, array_len=array_len
        );

        // Cast back to `felt*`.
        let state_updates_ptr = cast(state_updates_full, felt*);
        if (array_len == 0) {
            return ((state_updates_ptr - state_updates_start) / FullStateUpdateEntry.SIZE,0);
        }
        tempvar range_check_ptr = range_check_ptr;
        let (is_sorted) = is_sorted_recursively(array=ptr_to_storage_keys, array_len=array_len,index=0);
        if (is_sorted == 0 ){
            return ((state_updates_ptr - state_updates_start) / FullStateUpdateEntry.SIZE,0);
        }
        let tmp = log2_ceil(array_len);
        let (new_len) = pow(2,tmp);
        let zeros_to_add = new_len - array_len;
        let added_zeros = 0;
        let array_end_ptr = &ptr_to_storage_keys[array_len];
        add_zeros{array=array_end_ptr, added_zeros=zeros_to_add}(zeros_to_add=zeros_to_add);
        assert added_zeros = zeros_to_add;
        let (merkle_root) = merkle_tree_hash(array=ptr_to_storage_keys, array_len=new_len);
        return ((state_updates_ptr - state_updates_start) / FullStateUpdateEntry.SIZE,merkle_root);
    }
}

// Helper function for `serialize_da_changes` for the case `full_output == 0`.
func serialize_da_changes_inner{state_updates: StateUpdateEntry*}(
    update_ptr: DictAccess*, n_updates: felt, ptr_to_storage_keys: Slot*, array_len: felt
) {
    if (n_updates == 0) {
        return ();
    }
    if (array_len == 0) {
        return ();
    }
    // check if the key is in the array
    let is_key_in_array_result = is_key_in_array(key=update_ptr.key, array=ptr_to_storage_keys, array_len=array_len);
    if (is_key_in_array_result == 0) {
        return serialize_da_changes_inner(update_ptr=&update_ptr[1], n_updates=n_updates - 1, ptr_to_storage_keys=ptr_to_storage_keys, array_len=array_len);
    }

    if (update_ptr.prev_value == update_ptr.new_value) {
        tempvar state_updates = state_updates;
    } else {
        assert state_updates[0] = StateUpdateEntry(key=update_ptr.key, value=update_ptr.new_value);
        tempvar state_updates = &state_updates[1];
    }
    return serialize_da_changes_inner{state_updates=state_updates}(update_ptr=&update_ptr[1], n_updates=n_updates - 1, ptr_to_storage_keys=ptr_to_storage_keys, array_len=array_len);
}

// Helper function for `serialize_da_changes` for the case `full_output == 1`.
func serialize_da_changes_inner_full{state_updates: FullStateUpdateEntry*}(
    update_ptr: DictAccess*, n_updates: felt, ptr_to_storage_keys: Slot*, array_len: felt
) {
    if (n_updates == 0) {
        return ();
    }
    // check if the key is in the array
    if (array_len == 0) {
        return ();
    }

    let is_key_in_array_result = is_key_in_array(key=update_ptr.key, array=ptr_to_storage_keys, array_len=array_len);
    if (is_key_in_array_result == 0) {
        return serialize_da_changes_inner_full(update_ptr=&update_ptr[1], n_updates=n_updates - 1, ptr_to_storage_keys=ptr_to_storage_keys, array_len=array_len);
    }

    if (update_ptr.prev_value == update_ptr.new_value) {
        tempvar state_updates = state_updates;
    } else {
        assert state_updates[0] = FullStateUpdateEntry(
            key=update_ptr.key, prev_value=update_ptr.prev_value, new_value=update_ptr.new_value
        );

        tempvar state_updates = &state_updates[1];
    }
    return serialize_da_changes_inner_full(update_ptr=&update_ptr[1], n_updates=n_updates - 1, ptr_to_storage_keys=ptr_to_storage_keys, array_len=array_len);
}

// Writes the changed values in the contract state into `state_updates_ptr`
// to make this data available on-chain.
// See documentation in the beginning of the file for more information.
//
// Assumption: The dictionary `contract_state_changes_start` is squashed.
func output_contract_state{range_check_ptr, state_updates_ptr: felt*, poseidon_ptr: PoseidonBuiltin*}(
    contract_state_changes_start: DictAccess*, n_contract_state_changes: felt, full_output: felt,
    crdts: Crdt*,crdts_len: felt
) {
    alloc_locals;

    // Make room for number of modified contracts.
    let output_n_modified_contracts = [state_updates_ptr];
    let state_updates_ptr = state_updates_ptr + 1;
    let n_modified_contracts = 0;
    
    with n_modified_contracts {
        output_contract_state_inner{state_updates_ptr=state_updates_ptr}(
            n_contract_state_changes=n_contract_state_changes,
            state_changes=contract_state_changes_start,
            full_output=full_output,
            crdts=crdts,
            crdts_len=crdts_len,
        );
    }
    // Write number of modified contracts.
    assert output_n_modified_contracts = n_modified_contracts;

    return ();
}

// Helper function for `output_contract_state()`.
//
// Increases `n_modified_contracts` by the number of contracts with state changes.
func output_contract_state_inner{range_check_ptr, state_updates_ptr: felt*, n_modified_contracts:felt, poseidon_ptr: PoseidonBuiltin*}(
    n_contract_state_changes: felt, state_changes: DictAccess*, full_output: felt, 
    crdts: Crdt*,crdts_len: felt
) {
    if (n_contract_state_changes == 0) {
        return ();
    }
    alloc_locals;
    
    let is_key_in_crdts_result = is_key_in_crdts(key=state_changes.key, crdts=crdts, crdt_len=crdts_len);
    let index = crdts_len - is_key_in_crdts_result;
    if (is_key_in_crdts_result == 0) {
        return output_contract_state_inner(
            n_contract_state_changes=n_contract_state_changes - 1,
            state_changes=&state_changes[1],
            full_output=full_output,
            crdts=crdts,
            crdts_len=crdts_len,
        );
    }

    local prev_state: StateEntry* = cast(state_changes.prev_value, StateEntry*);
    local new_state: StateEntry* = cast(state_changes.new_value, StateEntry*);
    local prev_state_nonce = prev_state.nonce;
    local new_state_nonce = new_state.nonce;

    local storage_dict_start: DictAccess* = prev_state.storage_ptr;
    let storage_dict_end: DictAccess* = new_state.storage_ptr;
    local n_updates = (storage_dict_end - storage_dict_start) / DictAccess.SIZE;

    // Write contract state updates to output (state_updates_ptr).

    // Prepare updates.
    let contract_header = state_updates_ptr;

    // Class hash.
    local was_class_updated = is_not_zero(prev_state.class_hash - new_state.class_hash);
    const BASE_HEADER_SIZE = 3;
    if (full_output != 0) {
        // Write the previous and new class hash.
        assert contract_header[BASE_HEADER_SIZE] = prev_state.class_hash;
        assert contract_header[BASE_HEADER_SIZE + 1] = new_state.class_hash;
        // The offset of the storage diff from the header.
        tempvar storage_diff_offset = BASE_HEADER_SIZE + 2;
    } else {
        if (was_class_updated != 0) {
            // Write the new class hash.
            assert contract_header[BASE_HEADER_SIZE] = new_state.class_hash;
            // The offset of the storage diff from the header.
            tempvar storage_diff_offset = BASE_HEADER_SIZE + 1;
        } else {
            tempvar storage_diff_offset = BASE_HEADER_SIZE;
        }
    }

    let storage_diff: felt* = contract_header + storage_diff_offset;

    let (n_actual_updates, merkle_tree_hash) = serialize_da_changes{state_updates_ptr=storage_diff}(
        update_ptr=storage_dict_start, n_updates=n_updates, full_output=full_output, ptr_to_storage_keys=crdts[index].slots, array_len=crdts[index].slot_len
    );
    
    if (full_output == 0 and n_actual_updates == 0 and new_state_nonce == prev_state_nonce and
        was_class_updated == 0) {
        // There are no updates for this contract.
        return output_contract_state_inner(
            n_contract_state_changes=n_contract_state_changes - 1,
            state_changes=&state_changes[1],
            full_output=full_output,
            crdts=crdts,
            crdts_len=crdts_len,
        );
    }

    // Complete the header; Write contract address.
    
    assert contract_header[0] = state_changes.key;
    assert contract_header[1] = merkle_tree_hash;
    // Write the second word of the header.
    // Handle the nonce.
    assert_nn_le(new_state_nonce, NONCE_BOUND - 1);
    if (full_output == 0) {
        if (prev_state_nonce != new_state_nonce) {
            tempvar value = new_state_nonce;
        } else {
            tempvar value = 0;
        }
        tempvar range_check_ptr = range_check_ptr;
    } else {
        // Full output - write the new and old nonces.
        assert_nn_le(prev_state_nonce, NONCE_BOUND - 1);
        tempvar value = prev_state_nonce * NONCE_BOUND + new_state_nonce;
        tempvar range_check_ptr = range_check_ptr;
    }

    // Write the number of updates.
    local is_n_updates_small;
    %{ ids.is_n_updates_small = ids.n_actual_updates < ids.N_UPDATES_SMALL_PACKING_BOUND %}
    // Verify that the guessed value is 0 or 1.
    assert is_n_updates_small * is_n_updates_small = is_n_updates_small;
    if (is_n_updates_small != 0) {
        tempvar n_updates_bound = N_UPDATES_SMALL_PACKING_BOUND;
    } else {
        tempvar n_updates_bound = N_UPDATES_BOUND;
    }
    assert_nn_le(n_actual_updates, n_updates_bound - 1);
    let value = value * n_updates_bound + n_actual_updates;

    // Write 'is_n_updates_small' flag.
    let value = value * 2 + is_n_updates_small;

    // Write 'was class updated' flag.
    let value = value * 2 + was_class_updated;

    assert contract_header[2] = value;

    let state_updates_ptr = cast(storage_diff, felt*);
    let n_modified_contracts = n_modified_contracts + 1;

    return output_contract_state_inner(
        n_contract_state_changes=n_contract_state_changes - 1,
        state_changes=&state_changes[1],
        full_output=full_output,
        crdts=crdts,
        crdts_len=crdts_len,
    );
}

func is_key_in_array(key: felt, array: Slot*, array_len: felt) -> felt {
    if (array_len == 0) {
        return 0;  
    }

    if (key == array[0].key) {
        return 1;
    }

    return is_key_in_array(key=key, array=&array[1], array_len=array_len - 1);
}

func is_key_in_crdts(key: felt, crdts: Crdt*, crdt_len: felt) -> felt {
    if (crdt_len == 0) {
        return 0;
    }
    if (key == crdts[0].address) {
        return crdt_len;
    }
    return is_key_in_crdts(key=key, crdts=&crdts[1], crdt_len=crdt_len - 1);
}

// Function to add zeros to the array to make it a power of 2
func add_zeros{array: Slot*, added_zeros: felt}(zeros_to_add: felt) {
    if (zeros_to_add == 0) {
        return ();
    }

    assert array[added_zeros].key = 0;
    assert array[added_zeros].crdt_type = 0;
    let next_added_zeros = added_zeros;
    return add_zeros{array=array, added_zeros=next_added_zeros}(zeros_to_add=zeros_to_add - 1);
}


// Function to check if an array is sorted in ascending order recursively
func is_sorted_recursively{range_check_ptr}(array: Slot*, array_len: felt, index: felt) -> (is_sorted: felt) {
    // Base case: if we have reached the second last element
    if (index == array_len - 1) {
        return (is_sorted=1);
    }
    let x = is_le_felt(array[index].key, array[index + 1].key);

    if (x == 0) {
        return (is_sorted=0);
    }

    // Recurse for the rest of the array
    return is_sorted_recursively(array=array, array_len=array_len, index=index + 1);
}


// Function to hash the array to get the merkle root
func merkle_tree_hash{poseidon_ptr: PoseidonBuiltin*}(array: Slot*, array_len: felt) -> (
    res: felt
) {
    alloc_locals;
    if (array_len == 1) {
       let (new_array) = alloc();
        assert new_array[0] = array[0].key;
        assert new_array[1] = array[0].crdt_type;
        return poseidon_hash_many(2, new_array);
    }

    let new_array_len = (array_len / 2);
    let (left) = merkle_tree_hash(array=array, array_len=new_array_len);
    local left = left;

    let (right) = merkle_tree_hash(array=&array[new_array_len], array_len=new_array_len);
    local right = right;

    let (new_array) = alloc();
    new_array[0] = left;
    new_array[1] = right;

    let (res) = poseidon_hash_many(2, new_array);
    local res = res;
    return (res=res);
}