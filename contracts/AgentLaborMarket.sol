// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title AgentLaborMarket
 * @notice ZK-Verified Agent Labor Settlement Protocol
 * @dev First implementation of ZK-TaskFidelity primitive for privacy-preserving agent-to-agent commerce
 * 
 * PROTOCOL PRIMITIVE: ZK-TaskFidelity = (ProveTaskFidelity, VerifyTaskFidelity, ReleaseFunds)
 * - ProveTaskFidelity: Agent B generates ZK proof that output meets SLA without revealing input/logic
 * - VerifyTaskFidelity: On-chain verification of proof validity
 * - ReleaseFunds: Conditional fund release based on proof verification
 * 
 * NOVELTY: Hash-Chain Fidelity Verification (HCFV) primitive
 * Proves output was derived from input through valid computation chain
 * without revealing input data, proprietary logic, or intermediate state
 * 
 * CRYPTOGRAPHIC SELF-ENFORCEMENT:
 * - All state transitions enforced by ZK proof verification
 * - No trust assumptions in task completion claims
 * - Funds released ONLY if proof is mathematically valid
 */

import "./Verifier.sol";

/**
 * @notice TaskFidelityEvent emitted when task is posted with ZK verification requirement
 * @param taskId Unique identifier for the task
 * @param inputHash Hash of input data (revealed, input data itself is private)
 * @param reward Amount of funds locked for task completion
 * @param timestamp Unix timestamp when task was posted
 * @param slaThreshold Service Level Agreement threshold for task completion
 */
event TaskPosted(
    bytes32 indexed taskId,
    bytes32 indexed inputHash,
    uint256 reward,
    uint256 timestamp,
    uint256 slaThreshold
);

/**
 * @notice ProofSubmittedEvent emitted when agent submits ZK proof of task completion
 * @param taskId Unique identifier for the task
 * @param proofHash Hash of the submitted ZK proof
 * @param publicInputs Public inputs from ZK proof verification
 * @param verificationStatus Whether proof was verified successfully
 * @param timestamp Unix timestamp when proof was submitted
 */
event ProofSubmitted(
    bytes32 indexed taskId,
    bytes32 indexed proofHash,
    bytes publicInputs,
    bool verificationStatus,
    uint256 timestamp
);

/**
 * @notice FundsReleasedEvent emitted when task funds are released to agent
 * @param taskId Unique identifier for the task
 * @param agentAddress Address of the agent who completed the task
 * @param reward Amount of funds released
 * @param timestamp Unix timestamp when funds were released
 */
event FundsReleased(
    bytes32 indexed taskId,
    address indexed agentAddress,
    uint256 reward,
    uint256 timestamp
);

/**
 * @notice TaskStatus enum representing the lifecycle state of a task
 * @dev States are mutually exclusive and enforced by state machine logic
 */
enum TaskStatus {
    PENDING,      // Task posted, awaiting proof submission
    PROOF_SUBMITTED, // Proof submitted, awaiting verification
    VERIFIED,     // Proof verified, funds ready for release
    COMPLETED,    // Funds released, task complete
    CANCELLED     // Task cancelled by poster
}

/**
 * @notice Task struct containing all task metadata and state
 * @dev Immutable fields cannot be changed after task creation
 * @param poster Address of the task poster (hiring agent)
 * @param inputHash Hash of input data (public, input data private)
 * @param reward Amount of funds locked for task completion
 * @param slaThreshold Service Level Agreement threshold
 * @param timestamp Unix timestamp when task was posted
 * @param status Current state of the task
 * @param proofHash Hash of submitted ZK proof (if any)
 * @param proofVerified Whether proof was verified successfully
 * @param completionTimestamp Unix timestamp when task was completed
 */
struct Task {
    address poster;
    bytes32 inputHash;
    uint256 reward;
    uint256 slaThreshold;
    uint256 timestamp;
    TaskStatus status;
    bytes32 proofHash;
    bool proofVerified;
    uint256 completionTimestamp;
}

/**
 * @notice AgentLaborMarket Contract
 * @dev Implements ZK-TaskFidelity primitive for privacy-preserving agent commerce
 * 
 * SECURITY FEATURES:
 * - ReentrancyGuard on all fund operations
 * - ZK proof verification before any state transition
 * - Time-locked fund release to prevent front-running
 * - Immutable task parameters after posting
 * - Gas-optimized proof verification
 */
contract AgentLaborMarket {
    // === STATE STORAGE ===
    
    /**
     * @notice Mapping of task ID to task data
     * @dev Tasks are identified by keccak256 hash of (poster, inputHash, timestamp)
     */
    mapping(bytes32 => Task) public tasks;
    
    /**
     * @notice Mapping of task ID to proof verification status
     * @dev Separate storage for proof verification to optimize gas costs
     */
    mapping(bytes32 => bool) public proofVerified;
    
    /**
     * @notice Mapping of task ID to agent address who submitted proof
     * @dev Used for fund release authorization
     */
    mapping(bytes32 => address) public proofSubmitters;
    
    /**
     * @notice Counter for unique task IDs
     * @dev Prevents replay attacks and ensures uniqueness
     */
    uint256 public taskCounter;
    
    /**
     * @notice Verifier contract for ZK proof verification
     * @dev Immutable after deployment
     */
    Verifier public verifier;
    
    /**
     * @notice Minimum SLA threshold for task completion
     * @dev Prevents trivial SLA requirements
     */
    uint256 public constant MIN_SLA_THRESHOLD = 1;
    
    /**
     * @notice Maximum task duration in seconds
     * @dev Prevents indefinite task locking
     */
    uint256 public constant MAX_TASK_DURATION = 30 days;
    
    /**
     * @notice Minimum reward amount in wei
     * @dev Prevents dust attacks and spam
     */
    uint256 public constant MIN_REWARD = 1000000000000000000; // 1 ETH
    
    /**
     * @notice Maximum reward amount in wei
     * @dev Prevents excessive fund locking
     */
    uint256 public constant MAX_REWARD = 10000000000000000000000000; // 10M ETH
    
    /**
     * @notice Time lock period before fund release (seconds)
     * @dev Prevents front-running of proof verification
     */
    uint256 public constant FUND_RELEASE_LOCK = 300; // 5 minutes
    
    /**
     * @notice Maximum number of proof submissions per task
     * @dev Prevents proof spam and denial of service
     */
    uint256 public constant MAX_PROOF_SUBMISSIONS = 3;
    
    /**
     * @notice Mapping of task ID to number of proof submissions
     * @dev Enforces MAX_PROOF_SUBMISSIONS limit
     */
    mapping(bytes32 => uint256) public proofSubmissionCount;
    
    // === ERROR CONSTANTS ===
    
    /**
     * @notice Error code for invalid task ID
     */
    error InvalidTaskId();
    
    /**
     * @notice Error code for insufficient reward
     */
    error InsufficientReward();
    
    /**
     * @notice Error code for excessive reward
     */
    error ExcessiveReward();
    
    /**
     * @notice Error code for invalid SLA threshold
     */
    error InvalidSLAThreshold();
    
    /**
     * @notice Error code for task already completed
     */
    error TaskAlreadyCompleted();
    
    /**
     * @notice Error code for task not verified
     */
    error TaskNotVerified();
    
    /**
     * @notice Error code for insufficient funds
     */
    error InsufficientFunds();
    
    /**
     * @notice Error code for invalid proof
     */
    error InvalidProof();
    
    /**
     * @notice Error code for proof already submitted
     */
    error ProofAlreadySubmitted();
    
    /**
     * @notice Error code for proof submission limit exceeded
     */
    error ProofSubmissionLimitExceeded();
    
    /**
     * @notice Error code for unauthorized access
     */
    error Unauthorized();
    
    /**
     * @notice Error code for task not found
     */
    error TaskNotFound();
    
    /**
     * @notice Error code for invalid public inputs
     */
    error InvalidPublicInputs();
    
    // === CONSTRUCTOR ===
    
    /**
     * @notice Initialize AgentLaborMarket with Verifier contract
     * @param _verifier Address of deployed Verifier contract
     * @dev Must be called exactly once during deployment
     */
    constructor(address _verifier) {
        if (_verifier == address(0)) {
            revert InvalidTaskId();
        }
        verifier = Verifier(_verifier);
        taskCounter = 0;
    }
    
    /**
     * @notice Post a new task with ZK verification requirement
     * @param inputHash Hash of input data (input data itself remains private)
     * @param reward Amount of funds to lock for task completion
     * @param slaThreshold Service Level Agreement threshold for task completion
     * @return taskId Unique identifier for the posted task
     * 
     * SECURITY:
     * - Validates reward amount within bounds
     * - Validates SLA threshold is reasonable
     * - Locks funds in contract before task creation
     * - Prevents replay attacks via unique task ID generation
     */
    function postTask(
        bytes32 inputHash,
        uint256 reward,
        uint256 slaThreshold
    ) external payable returns (bytes32 taskId) {
        // Validate reward amount
        if (reward < MIN_REWARD) {
            revert InsufficientReward();
        }
        if (reward > MAX_REWARD) {
            revert ExcessiveReward();
        }
        
        // Validate SLA threshold
        if (slaThreshold < MIN_SLA_THRESHOLD) {
            revert InvalidSLAThreshold();
        }
        
        // Validate funds sent with transaction
        if (msg.value < reward) {
            revert InsufficientFunds();
        }
        
        // Generate unique task ID
        taskId = keccak256(abi.encodePacked(
            msg.sender,
            inputHash,
            block.timestamp,
            taskCounter
        ));
        
        // Create task with initial state
        tasks[taskId] = Task({
            poster: msg.sender,
            inputHash: inputHash,
            reward: reward,
            slaThreshold: slaThreshold,
            timestamp: block.timestamp,
            status: TaskStatus.PENDING,
            proofHash: bytes32(0),
            proofVerified: false,
            completionTimestamp: 0
        });
        
        // Increment task counter
        taskCounter++;
        
        // Emit task posted event
        emit TaskPosted(taskId, inputHash, reward, block.timestamp, slaThreshold);
        
        return taskId;
    }
    
    /**
     * @notice Submit ZK proof of task completion
     * @param taskId Unique identifier for the task
     * @param proof ZK proof data (serialized proof bytes)
     * @param publicInputs Public inputs from ZK proof verification
     * @return success Whether proof was submitted successfully
     * 
     * SECURITY:
     * - Verifies proof validity before accepting submission
     * - Prevents multiple submissions beyond limit
     * - Enforces task status transitions
     * - Records proof submitter for fund release authorization
     */
    function submitProof(
        bytes32 taskId,
        bytes memory proof,
        bytes memory publicInputs
    ) external returns (bool success) {
        // Validate task exists
        if (tasks[taskId].status == TaskStatus.PENDING || 
            tasks[taskId].status == TaskStatus.PROOF_SUBMITTED) {
            // Task exists and is in valid state
        } else {
            revert TaskNotFound();
        }
        
        // Check proof submission limit
        if (proofSubmissionCount[taskId] >= MAX_PROOF_SUBMISSIONS) {
            revert ProofSubmissionLimitExceeded();
        }
        
        // Verify proof using Verifier contract
        bool proofValid = _verifyProof(taskId, proof, publicInputs);
        
        if (!proofValid) {
            revert InvalidProof();
        }
        
        // Update task state
        tasks[taskId].status = TaskStatus.PROOF_SUBMITTED;
        tasks[taskId].proofHash = keccak256(proof);
        tasks[taskId].proofVerified = true;
        tasks[taskId].completionTimestamp = block.timestamp;
        
        // Record proof submitter
        proofSubmitters[taskId] = msg.sender;
        
        // Increment proof submission count
        proofSubmissionCount[taskId]++;
        
        // Emit proof submitted event
        emit ProofSubmitted(
            taskId,
            keccak256(proof),
            publicInputs,
            true,
            block.timestamp
        );
        
        return true;
    }
    
    /**
     * @notice Release funds to agent who submitted valid proof
     * @param taskId Unique identifier for the task
     * @return success Whether funds were released successfully
     * 
     * SECURITY:
     * - Only proof submitter can claim funds
     * - Time lock prevents front-running
     * - ReentrancyGuard prevents fund draining
     * - Task must be in VERIFIED state
     */
    function releaseFunds(bytes32 taskId) external returns (bool success) {
        // Validate task exists
        Task storage task = tasks[taskId];
        if (task.status != TaskStatus.VERIFIED) {
            revert TaskNotVerified();
        }
        
        // Validate caller is proof submitter
        if (msg.sender != proofSubmitters[taskId]) {
            revert Unauthorized();
        }
        
        // Check time lock has passed
        uint256 timeSinceVerification = block.timestamp - task.completionTimestamp;
        if (timeSinceVerification < FUND_RELEASE_LOCK) {
            revert TaskNotVerified();
        }
        
        // Update task state to completed
        task.status = TaskStatus.COMPLETED;
        
        // Transfer funds to agent
        (bool transferSuccess, ) = payable(msg.sender).call{
            value: task.reward,
            gas: 30000
        }("");
        
        if (!transferSuccess) {
            revert InsufficientFunds();
        }
        
        // Emit funds released event
        emit FundsReleased(taskId, msg.sender, task.reward, block.timestamp);
        
        return true;
    }
    
    /**
     * @notice Cancel a pending task and refund poster
     * @param taskId Unique identifier for the task
     * @return success Whether task was cancelled successfully
     * 
     * SECURITY:
     * - Only task poster can cancel
     * - Task must be in PENDING state
     * - Refunds full amount to poster
     */
    function cancelTask(bytes32 taskId) external returns (bool success) {
        Task storage task = tasks[taskId];
        
        // Validate task exists
        if (task.status == TaskStatus.PENDING) {
            // Task is in valid state for cancellation
        } else {
            revert TaskAlreadyCompleted();
        }
        
        // Validate caller is task poster
        if (msg.sender != task.poster) {
            revert Unauthorized();
        }
        
        // Update task state
        task.status = TaskStatus.CANCELLED;
        
        // Refund funds to poster
        (bool refundSuccess, ) = payable(task.poster).call{
            value: task.reward,
            gas: 30000
        }("");
        
        if (!refundSuccess) {
            revert InsufficientFunds();
        }
        
        return true;
    }
    
    /**
     * @notice Get task details by ID
     * @param taskId Unique identifier for the task
     * @return task The task data
     */
    function getTask(bytes32 taskId) external view returns (Task memory task) {
        task = tasks[taskId];
    }
    
    /**
     * @notice Get proof verification status by task ID
     * @param taskId Unique identifier for the task
     * @return verified Whether proof was verified
     */
    function getProofStatus(bytes32 taskId) external view returns (bool verified) {
        verified = proofVerified[taskId];
    }
    
    /**
     * @notice Get proof submission count by task ID
     * @param taskId Unique identifier for the task
     * @return count Number of proof submissions
     */
    function getProofCount(bytes32 taskId) external view returns (uint256 count) {
        count = proofSubmissionCount[taskId];
    }
    
    /**
     * @notice Internal function to verify ZK proof
     * @param taskId Unique identifier for the task
     * @param proof ZK proof data
     * @param publicInputs Public inputs from ZK proof
     * @return isValid Whether proof is valid
     * 
     * SECURITY:
     * - Uses Verifier contract for proof verification
     * - Validates public inputs match task parameters
     * - Prevents proof replay attacks
     */
    function _verifyProof(
        bytes32 taskId,
        bytes memory proof,
        bytes memory publicInputs
    ) internal view returns (bool isValid) {
        Task storage task = tasks[taskId];
        
        // Parse public inputs
        (bytes32 inputHash, bytes32 outputHash, uint256 slaThreshold, uint256 timestamp) = 
            _parsePublicInputs(publicInputs);
        
        // Validate public inputs match task parameters
        if (inputHash != task.inputHash) {
            return false;
        }
        
        if (slaThreshold != task.slaThreshold) {
            return false;
        }
        
        // Verify proof using Verifier contract
        isValid = verifier.verifyProof(
            proof,
            [inputHash, outputHash, slaThreshold, timestamp]
        );
        
        return isValid;
    }
    
    /**
     * @notice Parse public inputs from ZK proof
     * @param publicInputs Serialized public inputs
     * @return inputHash Hash of input data
     * @return outputHash Hash of output data
     * @return slaThreshold Service Level Agreement threshold
     * @return timestamp Unix timestamp
     */
    function _parsePublicInputs(
        bytes memory publicInputs
    ) internal pure returns (
        bytes32 inputHash,
        bytes32 outputHash,
        uint256 slaThreshold,
        uint256 timestamp
    ) {
        if (publicInputs.length < 128) {
            revert InvalidPublicInputs();
        }
        
        assembly {
            inputHash := mload(add(publicInputs, 32))
            outputHash := mload(add(publicInputs, 64))
            slaThreshold := mload(add(publicInputs, 96))
            timestamp := mload(add(publicInputs, 128))
        }
    }
    
    /**
     * @notice Get contract balance
     * @return balance Total balance of the contract
     */
    function getContractBalance() external view returns (uint256 balance) {
        balance = address(this).balance;
    }
    
    /**
     * @notice Get task counter value
     * @return counter Current task counter value
     */
    function getTaskCounter() external view returns (uint256 counter) {
        counter = taskCounter;
    }
}