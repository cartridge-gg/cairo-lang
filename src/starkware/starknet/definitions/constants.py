from starkware.crypto.signature.signature import FIELD_PRIME
from starkware.storage.storage import HASH_BYTES

STARKNET_LANG_DIRECTIVE = "starknet"

FIELD_SIZE = FIELD_PRIME
FIELD_SIZE_BITS = 251
ADDRESS_BITS = FIELD_SIZE_BITS
CONTRACT_ADDRESS_BITS = ADDRESS_BITS
NONCE_BITS = FIELD_SIZE_BITS

FELT_LOWER_BOUND = 0
FELT_UPPER_BOUND = FIELD_SIZE
BLOCK_HASH_LOWER_BOUND = 0
BLOCK_HASH_UPPER_BOUND = FIELD_SIZE
# Address 0 is reserved to distinguish an external transaction from an inner (L2<>L2) one.
L2_ADDRESS_LOWER_BOUND = 1
L2_ADDRESS_UPPER_BOUND = 2 ** CONTRACT_ADDRESS_BITS
CONTRACT_HASH_BYTES = HASH_BYTES
CONTRACT_HASH_UPPER_BOUND = FIELD_SIZE
CONTRACT_STATES_COMMITMENT_TREE_HEIGHT = FIELD_SIZE_BITS
ENTRY_POINT_OFFSET_LOWER_BOUND = 0
ENTRY_POINT_OFFSET_UPPER_BOUND = FIELD_SIZE
ENTRY_POINT_SELECTOR_LOWER_BOUND = 0
ENTRY_POINT_SELECTOR_UPPER_BOUND = FIELD_SIZE
EVENT_COMMITMENT_TREE_HEIGHT = 64
FEE_LOWER_BOUND = 0
FEE_UPPER_BOUND = 2 ** 128
# Default hash to fill the parent_hash field of the first block in the sequence.
GENESIS_PARENT_BLOCK_HASH = 0
GAS_PRICE_LOWER_BOUND = 0
GAS_PRICE_UPPER_BOUND = 2 ** 128
MAX_MESSAGE_TO_L1_LENGTH = 100
MAX_CALLDATA_LENGTH = 2 ** 30
NONCE_LOWER_BOUND = 0
NONCE_UPPER_BOUND = 2 ** NONCE_BITS
SYSCALL_SELECTOR_UPPER_BOUND = FIELD_SIZE
TRANSACTION_COMMITMENT_TREE_HEIGHT = 64
TRANSACTION_HASH_LOWER_BOUND = 0
TRANSACTION_HASH_UPPER_BOUND = FIELD_SIZE
TRANSACTION_VERSION_LOWER_BOUND = 0
TRANSACTION_VERSION_UPPER_BOUND = FIELD_SIZE
ADDRESS_LOWER_BOUND = 0
ADDRESS_UPPER_BOUND = 2 ** ADDRESS_BITS


# In order to identify transactions from unsupported versions.
TRANSACTION_VERSION = 0
# Indentation for transactions meant to query and not addressed to the OS.
QUERY_VERSION_BASE = 2 ** 128
QUERY_VERSION = QUERY_VERSION_BASE + TRANSACTION_VERSION

# OS-related constants.
L1_TO_L2_MSG_HEADER_SIZE = 5
L2_TO_L1_MSG_HEADER_SIZE = 3
DEPLOYMENT_INFO_HEADER_SIZE = 3

# StarkNet solidity contract-related constants.
N_DEFAULT_TOPICS = 1  # Events have one default topic.
# Excluding the default topic.
LOG_MSG_TO_L1_N_TOPICS = 2
CONSUMED_MSG_TO_L2_N_TOPICS = 3
# The headers include the payload size, so we need to add +1 since arrays are encoded with two
# additional parameters (offset and length) in solidity.
LOG_MSG_TO_L1_ENCODED_DATA_SIZE = (L2_TO_L1_MSG_HEADER_SIZE + 1) - LOG_MSG_TO_L1_N_TOPICS
CONSUMED_MSG_TO_L2_ENCODED_DATA_SIZE = (L1_TO_L2_MSG_HEADER_SIZE + 1) - CONSUMED_MSG_TO_L2_N_TOPICS

# The (empirical) L1 gas cost of each Cairo step.
N_STEPS_FEE_WEIGHT = 0.05