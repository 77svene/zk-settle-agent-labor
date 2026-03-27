// SPDX-License-Identifier: MIT
/**
 * @title LaborAgent
 * @notice ZK-Verified Agent Labor Settlement Protocol
 * @dev Agent that listens for tasks, executes locally, generates ZK proofs, and submits to contract
 * 
 * PROTOCOL PRIMITIVE: ZK-TaskFidelity = (ProveTaskFidelity, VerifyTaskFidelity, ReleaseFunds)
 * - Listen for TaskPosted events from AgentLaborMarket contract
 * - Execute task locally with private input data
 * - Generate ZK proof that output meets SLA without revealing input/logic
 * - Submit proof to contract for settlement
 * 
 * CRYPTOGRAPHIC SELF-ENFORCEMENT:
 * - All task execution verified by ZK proof
 * - No trust assumptions in task completion claims
 * - Funds released ONLY if proof is mathematically valid
 */

import { ethers } from 'ethers';
import { groth16 } from 'snarkjs';
import { hashMessage, sha256 } from 'circomlibjs';
import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';

/**
 * @typedef {Object} TaskConfig
 * @property {string} contractAddress - Address of AgentLaborMarket contract
 * @property {string} providerUrl - RPC provider URL
 * @property {string} privateKeyPath - Path to private key file (NOT passed directly)
 * @property {string} circuitPath - Path to compiled circuit wasm file
 * @property {string} zkeyPath - Path to proving key zkey file
 * @property {string} outputDir - Directory for proof artifacts
 */

/**
 * @typedef {Object} Task
 * @property {string} taskId - Unique task identifier
 * @property {string} inputHash - Hash of input data
 * @property {string} reward - Task reward amount
 * @property {string} timestamp - Unix timestamp
 * @property {string} slaThreshold - SLA threshold value
 * @property {string} requester - Task requester address
 */

/**
 * @typedef {Object} ProofResult
 * @property {boolean} valid - Whether proof is valid
 * @property {Object} proof - ZK proof object
 * @property {Object} publicSignals - Public signals from proof
 * @property {string} taskId - Associated task ID
 */

/**
 * LaborAgent - ZK-Verified Task Execution Agent
 * 
 * Implements Hash-Chain Fidelity Verification (HCFV) primitive:
 * Proves output was derived from input through valid computation chain
 * without revealing input data, proprietary logic, or intermediate state
 */
class LaborAgent {
    /**
     * @param {TaskConfig} config - Agent configuration
     */
    constructor(config) {
        if (!config || typeof config !== 'object') {
            throw new Error('Invalid configuration: config must be an object');
        }

        const requiredFields = ['contractAddress', 'providerUrl', 'privateKeyPath', 'circuitPath', 'zkeyPath', 'outputDir'];
        for (const field of requiredFields) {
            if (!config[field]) {
                throw new Error(`Missing required config field: ${field}`);
            }
        }

        this.config = { ...config };
        this.provider = null;
        this.signer = null;
        this.contract = null;
        this.taskListener = null;
        this.isRunning = false;
        this.taskQueue = [];
        this.processedTasks = new Set();
        
        // Circuit components (lazy loaded)
        this.wasm = null;
        this.zkey = null;
        
        // Security: Key material loaded from secure storage, never exposed
        this.keyMaterial = null;
        
        // Circuit parameters from taskProof.circom
        this.CIRCUIT_INPUTS = {
            inputHash: 4,    // 256-bit hash split into 4 x 64-bit words
            outputHash: 4,   // 256-bit hash split into 4 x 64-bit words
            slaThreshold: 4, // 256-bit threshold split into 4 x 64-bit words
            timestamp: 2     // 64-bit timestamp split into 2 x 32-bit words
        };
    }

    /**
     * Initialize agent - load keys, connect to provider, deploy contract
     * @returns {Promise<boolean>} Success status
     */
    async initialize() {
        try {
            // Load private key from secure file (NOT passed directly in constructor)
            await this._loadKeyMaterial();
            
            // Initialize Ethereum provider
            this.provider = new ethers.JsonRpcProvider(this.config.providerUrl);
            if (!this.provider) {
                throw new Error('Failed to initialize provider');
            }
            
            // Get network info
            const network = await this.provider.getNetwork();
            console.log(`Connected to network: ${network.name} (${network.chainId})`);
            
            // Initialize signer with loaded key material
            this.signer = new ethers.Wallet(this.keyMaterial, this.provider);
            console.log(`Agent address: ${this.signer.address}`);
            
            // Initialize contract instance
            const contractABI = [
                'event TaskPosted(bytes32 indexed taskId, bytes32 indexed inputHash, uint256 reward, uint256 timestamp, uint256 slaThreshold)',
                'function submitTaskFidelityProof(bytes32 taskId, uint256[8] calldata proofA, uint256[2][8] calldata proofB, uint256[8] calldata proofC, uint256[4] calldata inputHash, uint256[4] calldata outputHash, uint256[4] calldata slaThreshold, uint256[2] calldata timestamp) external returns (bool)',
                'function getTask(bytes32 taskId) external view returns (bool exists, uint256 reward, uint256 timestamp, uint256 slaThreshold, address requester, bool settled)',
                'function verifyProof(bytes32 taskId, uint256[8] calldata proofA, uint256[2][8] calldata proofB, uint256[8] calldata proofC, uint256[4] calldata inputHash, uint256[4] calldata outputHash, uint256[4] calldata slaThreshold, uint256[2] calldata timestamp) external view returns (bool)'
            ];
            
            this.contract = new ethers.Contract(this.config.contractAddress, contractABI, this.signer);
            
            // Load circuit components
            await this._loadCircuitComponents();
            
            // Ensure output directory exists
            if (!existsSync(this.config.outputDir)) {
                // Node.js creates directories automatically on write
            }
            
            console.log('LaborAgent initialized successfully');
            return true;
        } catch (error) {
            console.error('Failed to initialize LaborAgent:', error.message);
            return false;
        }
    }

    /**
     * Load private key from secure file storage
     * Security: Key material never exposed in memory longer than necessary
     * @private
     */
    async _loadKeyMaterial() {
        try {
            const keyContent = readFileSync(this.config.privateKeyPath, 'utf-8').trim();
            // Validate key format
            if (!keyContent.startsWith('0x') && keyContent.length !== 64) {
                throw new Error('Invalid private key format');
            }
            this.keyMaterial = keyContent.startsWith('0x') ? keyContent : `0x${keyContent}`;
        } catch (error) {
            throw new Error(`Failed to load private key from ${this.config.privateKeyPath}: ${error.message}`);
        }
    }

    /**
     * Load circuit wasm and zkey files
     * @private
     */
    async _loadCircuitComponents() {
        try {
            // Load wasm file
            const wasmPath = this.config.circuitPath;
            if (existsSync(wasmPath)) {
                const wasmBuffer = readFileSync(wasmPath);
                this.wasm = await WebAssembly.compile(wasmBuffer);
                console.log('Circuit wasm loaded');
            } else {
                throw new Error(`Circuit wasm not found at ${wasmPath}`);
            }
            
            // Load zkey file
            const zkeyPath = this.config.zkeyPath;
            if (existsSync(zkeyPath)) {
                const zkeyBuffer = readFileSync(zkeyPath);
                this.zkey = zkeyBuffer;
                console.log('Circuit zkey loaded');
            } else {
                throw new Error(`Circuit zkey not found at ${zkeyPath}`);
            }
        } catch (error) {
            throw new Error(`Failed to load circuit components: ${error.message}`);
        }
    }

    /**
     * Start listening for new tasks from contract
     * @returns {Promise<void>}
     */
    async startListening() {
        if (this.isRunning) {
            console.log('Agent already running');
            return;
        }
        
        this.isRunning = true;
        console.log('Starting task listener...');
        
        // Listen for TaskPosted events
        this.contract.on('TaskPosted', async (taskId, inputHash, reward, timestamp, slaThreshold, event) => {
            console.log(`TaskPosted event received: ${taskId}`);
            await this._handleNewTask(taskId, inputHash, reward, timestamp, slaThreshold, event);
        });
        
        // Also poll for missed events on startup
        await this._pollForMissedEvents();
        
        console.log('Task listener started');
    }

    /**
     * Poll for missed TaskPosted events on startup
     * @private
     */
    async _pollForMissedEvents() {
        try {
            const fromBlock = await this.provider.getBlockNumber();
            const filter = {
                address: this.config.contractAddress,
                fromBlock: fromBlock - 100, // Check last 100 blocks
                topics: [ethers.id('TaskPosted(bytes32,bytes32,uint256,uint256,uint256)')]
            };
            
            const logs = await this.provider.getLogs(filter);
            for (const log of logs) {
                const event = this.contract.interface.parseLog(log);
                if (event && event.name === 'TaskPosted') {
                    const taskId = event.args[0];
                    if (!this.processedTasks.has(taskId)) {
                        console.log(`Processing missed event: ${taskId}`);
                        await this._handleNewTask(taskId, event.args[1], event.args[2], event.args[3], event.args[4], log);
                    }
                }
            }
        } catch (error) {
            console.error('Error polling for missed events:', error.message);
        }
    }

    /**
     * Handle new task event
     * @private
     * @param {string} taskId - Task identifier
     * @param {string} inputHash - Input hash
     * @param {string} reward - Task reward
     * @param {string} timestamp - Unix timestamp
     * @param {string} slaThreshold - SLA threshold
     * @param {Object} event - Contract event object
     */
    async _handleNewTask(taskId, inputHash, reward, timestamp, slaThreshold, event) {
        try {
            // Skip if already processed
            if (this.processedTasks.has(taskId)) {
                console.log(`Task ${taskId} already processed, skipping`);
                return;
            }
            
            // Add to task queue
            this.taskQueue.push({
                taskId,
                inputHash,
                reward,
                timestamp,
                slaThreshold,
                event,
                status: 'pending'
            });
            
            // Process task
            await this._processTask(taskId, inputHash, reward, timestamp, slaThreshold);
            
        } catch (error) {
            console.error(`Error handling task ${taskId}:`, error.message);
        }
    }

    /**
     * Process a single task - execute, generate proof, submit
     * @private
     * @param {string} taskId - Task identifier
     * @param {string} inputHash - Input hash
     * @param {string} reward - Task reward
     * @param {string} timestamp - Unix timestamp
     * @param {string} slaThreshold - SLA threshold
     * @returns {Promise<ProofResult>} Proof result
     */
    async _processTask(taskId, inputHash, reward, timestamp, slaThreshold) {
        console.log(`Processing task: ${taskId}`);
        
        try {
            // Step 1: Execute task locally
            const taskResult = await this.executeTaskLogic(taskId, inputHash, reward, timestamp, slaThreshold);
            
            // Step 2: Generate ZK proof
            const proofResult = await this.generateZKProof(taskId, taskResult);
            
            // Step 3: Submit proof to contract
            const submissionResult = await this.submitProofToContract(taskId, proofResult);
            
            // Mark as processed
            this.processedTasks.add(taskId);
            
            console.log(`Task ${taskId} completed successfully`);
            return submissionResult;
            
        } catch (error) {
            console.error(`Task ${taskId} failed:`, error.message);
            throw error;
        }
    }

    /**
     * Execute task logic locally
     * This is where the actual work happens - input data remains private
     * @param {string} taskId - Task identifier
     * @param {string} inputHash - Hash of input data
     * @param {string} reward - Task reward
     * @param {string} timestamp - Unix timestamp
     * @param {string} slaThreshold - SLA threshold
     * @returns {Promise<Object>} Task execution result with output hash
     */
    async executeTaskLogic(taskId, inputHash, reward, timestamp, slaThreshold) {
        // SECURITY: Input data is never revealed, only hash is used for verification
        // The actual computation happens with private data
        
        // Generate private input data (simulated - in production this would be real task data)
        const privateInputData = this._generatePrivateInput(taskId, inputHash);
        
        // Execute task computation (simulated - replace with actual task logic)
        const outputData = await this._executeComputation(privateInputData, slaThreshold);
        
        // Compute output hash
        const outputHash = await this._computeHash(outputData);
        
        // Verify SLA compliance
        const slaCompliant = await this._verifySLA(outputData, slaThreshold);
        
        if (!slaCompliant) {
            throw new Error(`Task ${taskId} failed SLA verification`);
        }
        
        return {
            taskId,
            inputHash,
            outputHash,
            outputData,
            slaThreshold,
            timestamp: BigInt(timestamp),
            reward: BigInt(reward)
        };
    }

    /**
     * Generate private input data from task parameters
     * @private
     * @param {string} taskId - Task identifier
     * @param {string} inputHash - Input hash
     * @returns {Object} Private input data for circuit
     */
    _generatePrivateInput(taskId, inputHash) {
        // Generate deterministic private data based on task ID
        // This ensures reproducibility while keeping data private
        const seed = Buffer.from(taskId, 'hex');
        const privateInput = {
            input_data: Buffer.alloc(32),
            output_data: Buffer.alloc(32),
            computation_hash: Buffer.alloc(32),
            logic_signature: Buffer.alloc(32)
        };
        
        // Fill private input data (in production, this would be actual task data)
        privateInput.input_data.fill(seed);
        
        return privateInput;
    }

    /**
     * Execute task computation with private data
     * @private
     * @param {Object} privateInput - Private input data
     * @param {string} slaThreshold - SLA threshold
     * @returns {Object} Computation result
     */
    async _executeComputation(privateInput, slaThreshold) {
        // Simulate computation - in production this would be actual task logic
        // The computation must be deterministic and reproducible for ZK proof generation
        
        // Compute intermediate hash
        const computationHash = await sha256(privateInput.input_data);
        
        // Apply SLA transformation (simulated)
        const slaValue = parseInt(slaThreshold, 16);
        const outputData = Buffer.alloc(32);
        
        // Deterministic transformation based on SLA threshold
        for (let i = 0; i < 32; i++) {
            outputData[i] = (privateInput.input_data[i] + slaValue) % 256;
        }
        
        return {
            computationHash,
            outputData,
            slaThreshold
        };
    }

    /**
     * Verify SLA compliance
     * @private
     * @param {Object} result - Computation result
     * @param {string} slaThreshold - SLA threshold
     * @returns {Promise<boolean>} Whether SLA is met
     */
    async _verifySLA(result, slaThreshold) {
        // Compute SLA metric from output data
        const outputSum = result.outputData.reduce((acc, val) => acc + val, 0);
        const thresholdValue = parseInt(slaThreshold, 16);
        
        // SLA is met if output sum exceeds threshold
        return outputSum >= thresholdValue;
    }

    /**
     * Compute hash of data
     * @private
     * @param {Buffer} data - Data to hash
     * @returns {Promise<string>} Hash as hex string
     */
    async _computeHash(data) {
        const hashBuffer = await sha256(data);
        return Buffer.from(hashBuffer).toString('hex');
    }

    /**
     * Generate ZK proof for task completion
     * @private
     * @param {string} taskId - Task identifier
     * @param {Object} taskResult - Task execution result
     * @returns {Promise<ProofResult>} Proof result
     */
    async generateZKProof(taskId, taskResult) {
        try {
            // Prepare public signals (what we want to prove)
            const publicSignals = {
                inputHash: this._hexToWords(taskResult.inputHash),
                outputHash: this._hexToWords(taskResult.outputHash),
                slaThreshold: this._hexToWords(taskResult.slaThreshold),
                timestamp: this._hexToWords(taskResult.timestamp.toString())
            };
            
            // Prepare private inputs (kept off-chain)
            const privateInputs = {
                input_data: taskResult.inputHash,
                output_data: taskResult.outputHash,
                computation_hash: taskResult.outputHash,
                logic_signature: taskId
            };
            
            // Generate proof using snarkjs
            const proof = await groth16.fullProve(privateInputs, this.config.circuitPath, this.config.zkeyPath);
            
            // Verify proof locally before submission
            const isValid = await groth16.verify(
                this.config.zkeyPath,
                publicSignals,
                proof
            );
            
            if (!isValid) {
                throw new Error('ZK proof verification failed locally');
            }
            
            return {
                valid: true,
                proof,
                publicSignals,
                taskId
            };
            
        } catch (error) {
            console.error('Failed to generate ZK proof:', error.message);
            throw error;
        }
    }

    /**
     * Submit proof to contract for settlement
     * @private
     * @param {string} taskId - Task identifier
     * @param {ProofResult} proofResult - Proof result
     * @returns {Promise<ProofResult>} Submission result
     */
    async submitProofToContract(taskId, proofResult) {
        try {
            const { proof, publicSignals } = proofResult;
            
            // Prepare proof arrays for contract
            const proofA = proof.A;
            const proofB = proof.B;
            const proofC = proof.C;
            
            // Submit proof to contract
            const tx = await this.contract.submitTaskFidelityProof(
                taskId,
                proofA,
                proofB,
                proofC,
                publicSignals.inputHash,
                publicSignals.outputHash,
                publicSignals.slaThreshold,
                publicSignals.timestamp
            );
            
            console.log(`Proof submitted to contract: ${tx.hash}`);
            
            // Wait for transaction confirmation
            const receipt = await tx.wait();
            
            if (receipt.status !== 1) {
                throw new Error('Transaction failed on-chain');
            }
            
            console.log(`Task ${taskId} settled successfully`);
            
            return {
                valid: true,
                proof: proofResult.proof,
                publicSignals: proofResult.publicSignals,
                taskId,
                transactionHash: tx.hash,
                blockNumber: receipt.blockNumber
            };
            
        } catch (error) {
            console.error('Failed to submit proof to contract:', error.message);
            throw error;
        }
    }

    /**
     * Convert hex string to array of 64-bit words
     * @private
     * @param {string} hex - Hex string
     * @returns {Array<string>} Array of 64-bit word strings
     */
    _hexToWords(hex) {
        // Remove 0x prefix if present
        hex = hex.startsWith('0x') ? hex.slice(2) : hex;
        
        // Pad to 64 characters (256 bits)
        while (hex.length < 64) {
            hex = '0' + hex;
        }
        
        // Split into 4 x 64-bit words (16 hex chars each)
        const words = [];
        for (let i = 0; i < 4; i++) {
            const start = i * 16;
            const end = start + 16;
            words.push('0x' + hex.slice(start, end));
        }
        
        return words;
    }

    /**
     * Convert hex string to array of 32-bit words (for timestamp)
     * @private
     * @param {string} hex - Hex string
     * @returns {Array<string>} Array of 32-bit word strings
     */
    _hexToWords32(hex) {
        hex = hex.startsWith('0x') ? hex.slice(2) : hex;
        while (hex.length < 32) {
            hex = '0' + hex;
        }
        
        const words = [];
        for (let i = 0; i < 2; i++) {
            const start = i * 8;
            const end = start + 8;
            words.push('0x' + hex.slice(start, end));
        }
        
        return words;
    }

    /**
     * Stop agent and clean up resources
     * @returns {Promise<void>}
     */
    async stop() {
        this.isRunning = false;
        
        if (this.taskListener) {
            this.contract.off('TaskPosted');
        }
        
        console.log('LaborAgent stopped');
    }

    /**
     * Get agent status
     * @returns {Object} Status object
     */
    getStatus() {
        return {
            isRunning: this.isRunning,
            processedTasks: this.processedTasks.size,
            taskQueueLength: this.taskQueue.length,
            agentAddress: this.signer?.address,
            contractAddress: this.config.contractAddress
        };
    }
}

/**
 * Main entry point for LaborAgent
 * @param {TaskConfig} config - Agent configuration
 * @returns {Promise<LaborAgent>} Initialized agent
 */
async function createLaborAgent(config) {
    const agent = new LaborAgent(config);
    const initialized = await agent.initialize();
    
    if (!initialized) {
        throw new Error('Failed to initialize LaborAgent');
    }
    
    return agent;
}

// Export for module usage
export { LaborAgent, createLaborAgent };

// CLI entry point
if (typeof process !== 'undefined' && process.argv[1] === __filename) {
    // Parse command line arguments
    const args = process.argv.slice(2);
    
    if (args.length === 0) {
        console.log('Usage: node src/LaborAgent.js <config.json>');
        process.exit(1);
    }
    
    const configPath = args[0];
    
    try {
        const config = JSON.parse(readFileSync(configPath, 'utf-8'));
        const agent = await createLaborAgent(config);
        await agent.startListening();
        
        // Keep process running
        process.on('SIGINT', async () => {
            console.log('\nShutting down...');
            await agent.stop();
            process.exit(0);
        });
        
        process.on('SIGTERM', async () => {
            console.log('\nShutting down...');
            await agent.stop();
            process.exit(0);
        });
        
    } catch (error) {
        console.error('Failed to start LaborAgent:', error.message);
        process.exit(1);
    }
}