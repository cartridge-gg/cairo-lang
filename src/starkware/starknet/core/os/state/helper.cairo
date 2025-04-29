from starkware.cairo.common.cairo_builtins import PoseidonBuiltin
from starkware.cairo.common.builtin_poseidon.poseidon import poseidon_hash_many
from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.math_cmp import is_le_felt


// Function to add zeros to the array to make it a power of 2
func add_zeros{array: felt*, added_zeros: felt}(zeros_to_add: felt) {
    if (zeros_to_add == 0) {
        return ();
    }

    assert array[added_zeros] = 0;
    assert array[added_zeros + 1] = 0;
    let next_added_zeros = added_zeros + 2;
    return add_zeros{array=array, added_zeros=next_added_zeros}(zeros_to_add=zeros_to_add - 1);
}


// Function to hash the array to get the merkle root
func merkle_tree_hash{poseidon_ptr: PoseidonBuiltin*}(array: felt*, array_len: felt) -> (
    res: felt
) {
    alloc_locals;
    if (array_len == 1) {
        
        return poseidon_hash_many(1, array);
    }

    let (left) = merkle_tree_hash(array=array, array_len=array_len / 2);
    local left = left;

    let (right) = merkle_tree_hash(array=&array[array_len / 2], array_len=array_len / 2);
    local right = right;

    let (new_array) = alloc();
    new_array[0] = left;
    new_array[1] = right;

    let (res) = poseidon_hash_many(2, new_array);
    local res = res;
    return (res=res);
}

// Function to check if an array is sorted in ascending order recursively
func is_sorted_recursively{range_check_ptr}(array: felt*, array_len: felt, index: felt) -> (is_sorted: felt) {
    // Base case: if we have reached the second last element
    if (index == array_len - 1) {
        return (is_sorted=1);
    }
    let x = is_le_felt(array[index], array[index + 1]);

    if (x == 0) {
        return (is_sorted=0);
    }

    // Recurse for the rest of the array
    return is_sorted_recursively(array=array, array_len=array_len, index=index + 1);
}

func sort_array(array: felt*, array_len: felt) -> felt* {
    let (sorted_array_1: felt*) = alloc();
    %{
        array_len = ids.array_len
        array = []
        for i in range(array_len):
            array.append(memory[ids.array+i])
        array.sort()
        for i in range(array_len):
            memory[ids.sorted_array_1+i] = array[i]
    %}

    return sorted_array_1;
}
