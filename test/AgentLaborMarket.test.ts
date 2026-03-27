// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import { expect } from "chai";
import { ethers } from "hardhat";
import { AgentLaborMarket } from "../typechain-types";
import { Verifier } from "../typechain-types";
import { SignerWithAddress } from "@nomicfoundation/hardhat-ethers/signers";
import * as snarkjs from "snarkjs";
import * as fs from "fs";
import * as path from "path";

describe("AgentLaborMarket - ZK-TaskFidelity Protocol", function () {
  let market: AgentLaborMarket;
  let verifier: Verifier;
  let owner: SignerWithAddress;
  let client: SignerWithAddress;
  let agent: SignerWithAddress;
  let maliciousAgent: SignerWithAddress;

  const TASK_INPUT_DATA = "client_secret_data_12345";
  const TASK_OUTPUT_DATA = "agent_computed_result_67890";
  const SLA_THRESHOLD = 85;
  const REWARD_AMOUNT = ethers.parseEther("1.0");
  const CIRCUIT_PATH = path.join(__dirname, "..", "circuits", "taskProof");
  const ZKEY_PATH = path.join(__dirname, "..", "circuits", "taskProof_final.zkey");
  const VKEY_PATH = path.join(__dirname, "..", "circuits", "verification_key.json");

  const TEST_INPUT_HASH = "0x" + "0".repeat(64);
  const TEST_OUTPUT_HASH = "0x" + "1".repeat(64);
  const TEST_SLA_THRESHOLD = 85;
  const TEST_TIMESTAMP = 1735689600;

  const INVALID_PROOF_INPUT_HASH = "0x" + "a".repeat(64);
  const INVALID_PROOF_OUTPUT_HASH = "0x" + "b".repeat(64);

  before(async function () {
    [owner, client, agent, maliciousAgent] = await ethers.getSigners();

    const VerifierFactory = await ethers.getContractFactory("Verifier");
    verifier = await VerifierFactory.deploy();
    await verifier.waitForDeployment();

    const MarketFactory = await ethers.getContractFactory("AgentLaborMarket");
    market = await MarketFactory.deploy(verifier.getAddress());
    await market.waitForDeployment();

    await market.connect(client).fundMarket({ value: ethers.parseEther("100.0") });
  });

  describe("Task Posting & ZK-TaskFidelity Primitive", function () {
    it("Should post task with valid ZK verification requirement", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      const tx = await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const receipt = await tx.wait();
      const event = receipt?.logs.find(
        (log: any) => log.fragment?.name === "TaskPosted"
      ) as any;

      expect(event.args.taskId).to.equal(taskId);
      expect(event.args.inputHash).to.equal(inputHash);
      expect(event.args.reward).to.equal(REWARD_AMOUNT);
      expect(event.args.slaThreshold).to.equal(SLA_THRESHOLD);
    });

    it("Should reject task posting with insufficient funds", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));
      const insufficientReward = ethers.parseEther("0.001");

      await expect(
        market
          .connect(client)
          .postTask(taskId, inputHash, insufficientReward, SLA_THRESHOLD, {
            value: insufficientReward,
          })
      ).to.be.revertedWith("Insufficient funds locked");
    });

    it("Should reject duplicate taskId submission", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      await expect(
        market
          .connect(client)
          .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
            value: REWARD_AMOUNT,
          })
      ).to.be.revertedWith("Task already exists");
    });
  });

  describe("ZK Proof Submission & Verification", function () {
    it("Should accept valid ZK proof and release funds", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const proof = await generateValidProof(
        inputHash,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      const tx = await market
        .connect(agent)
        .submitProof(taskId, proof, [
          TEST_INPUT_HASH,
          TEST_OUTPUT_HASH,
          TEST_SLA_THRESHOLD,
          TEST_TIMESTAMP,
        ]);

      const receipt = await tx.wait();
      const event = receipt?.logs.find(
        (log: any) => log.fragment?.name === "TaskCompleted"
      ) as any;

      expect(event.args.taskId).to.equal(taskId);
      expect(event.args.agent).to.equal(agent.address);
      expect(event.args.reward).to.equal(REWARD_AMOUNT);
    });

    it("Should reject invalid ZK proof with mismatched input hash", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const proof = await generateValidProof(
        INVALID_PROOF_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      await expect(
        market
          .connect(agent)
          .submitProof(taskId, proof, [
            INVALID_PROOF_INPUT_HASH,
            TEST_OUTPUT_HASH,
            TEST_SLA_THRESHOLD,
            TEST_TIMESTAMP,
          ])
      ).to.be.revertedWith("ZK proof verification failed");
    });

    it("Should reject invalid ZK proof with mismatched output hash", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const proof = await generateValidProof(
        TEST_INPUT_HASH,
        INVALID_PROOF_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      await expect(
        market
          .connect(agent)
          .submitProof(taskId, proof, [
            TEST_INPUT_HASH,
            INVALID_PROOF_OUTPUT_HASH,
            SLA_THRESHOLD,
            TEST_TIMESTAMP,
          ])
      ).to.be.revertedWith("ZK proof verification failed");
    });

    it("Should reject proof with SLA threshold below requirement", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const proof = await generateValidProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        50,
        TEST_TIMESTAMP
      );

      await expect(
        market
          .connect(agent)
          .submitProof(taskId, proof, [
            TEST_INPUT_HASH,
            TEST_OUTPUT_HASH,
            50,
            TEST_TIMESTAMP,
          ])
      ).to.be.revertedWith("SLA threshold not met");
    });

    it("Should reject proof from unauthorized agent", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const proof = await generateValidProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      await expect(
        market
          .connect(maliciousAgent)
          .submitProof(taskId, proof, [
            TEST_INPUT_HASH,
            TEST_OUTPUT_HASH,
            SLA_THRESHOLD,
            TEST_TIMESTAMP,
          ])
      ).to.be.revertedWith("Only task owner or authorized agent can submit proof");
    });

    it("Should reject proof for non-existent task", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      const proof = await generateValidProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      await expect(
        market
          .connect(agent)
          .submitProof(taskId, proof, [
            TEST_INPUT_HASH,
            TEST_OUTPUT_HASH,
            SLA_THRESHOLD,
            TEST_TIMESTAMP,
          ])
      ).to.be.revertedWith("Task not found");
    });
  });

  describe("Adversarial Fund Release Scenarios", function () {
    it("Should prevent double-spend of task funds", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const proof = await generateValidProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      await market
        .connect(agent)
        .submitProof(taskId, proof, [
          TEST_INPUT_HASH,
          TEST_OUTPUT_HASH,
          SLA_THRESHOLD,
          TEST_TIMESTAMP,
        ]);

      const secondProof = await generateValidProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      await expect(
        market
          .connect(agent)
          .submitProof(taskId, secondProof, [
            TEST_INPUT_HASH,
            TEST_OUTPUT_HASH,
            SLA_THRESHOLD,
            TEST_TIMESTAMP,
          ])
      ).to.be.revertedWith("Task already completed");
    });

    it("Should prevent fund drain via malicious proof manipulation", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const maliciousProof = await generateMaliciousProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      await expect(
        market
          .connect(agent)
          .submitProof(taskId, maliciousProof, [
            TEST_INPUT_HASH,
            TEST_OUTPUT_HASH,
            SLA_THRESHOLD,
            TEST_TIMESTAMP,
          ])
      ).to.be.revertedWith("ZK proof verification failed");
    });

    it("Should prevent timestamp manipulation attacks", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const futureTimestamp = 9999999999;
      const proof = await generateValidProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        futureTimestamp
      );

      await expect(
        market
          .connect(agent)
          .submitProof(taskId, proof, [
            TEST_INPUT_HASH,
            TEST_OUTPUT_HASH,
            SLA_THRESHOLD,
            futureTimestamp,
          ])
      ).to.be.revertedWith("Timestamp validation failed");
    });

    it("Should handle insufficient market funds gracefully", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const proof = await generateValidProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      await market
        .connect(agent)
        .submitProof(taskId, proof, [
          TEST_INPUT_HASH,
          TEST_OUTPUT_HASH,
          SLA_THRESHOLD,
          TEST_TIMESTAMP,
        ]);

      const marketBalance = await ethers.provider.getBalance(market.getAddress());
      expect(marketBalance).to.be.lessThan(REWARD_AMOUNT);
    });
  });

  describe("Protocol Primitive Composability", function () {
    it("Should allow multiple tasks with different SLA thresholds", async function () {
      const taskId1 = ethers.randomBytes(32);
      const taskId2 = ethers.randomBytes(32);
      const inputHash1 = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));
      const inputHash2 = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA + "2"));

      await market
        .connect(client)
        .postTask(taskId1, inputHash1, REWARD_AMOUNT, 80, {
          value: REWARD_AMOUNT,
        });

      await market
        .connect(client)
        .postTask(taskId2, inputHash2, REWARD_AMOUNT, 95, {
          value: REWARD_AMOUNT,
        });

      const proof1 = await generateValidProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        80,
        TEST_TIMESTAMP
      );

      const proof2 = await generateValidProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        95,
        TEST_TIMESTAMP
      );

      await market
        .connect(agent)
        .submitProof(taskId1, proof1, [
          TEST_INPUT_HASH,
          TEST_OUTPUT_HASH,
          80,
          TEST_TIMESTAMP,
        ]);

      await market
        .connect(agent)
        .submitProof(taskId2, proof2, [
          TEST_INPUT_HASH,
          TEST_OUTPUT_HASH,
          95,
          TEST_TIMESTAMP,
        ]);

      const task1 = await market.getTask(taskId1);
      const task2 = await market.getTask(taskId2);

      expect(task1.completed).to.be.true;
      expect(task2.completed).to.be.true;
    });

    it("Should support task cancellation by owner before completion", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const refundAmount = await market.getTaskFunds(taskId);
      await market.connect(client).cancelTask(taskId);

      const task = await market.getTask(taskId);
      expect(task.completed).to.be.false;
      expect(task.canceled).to.be.true;

      const clientBalance = await ethers.provider.getBalance(client.address);
      expect(clientBalance).to.be.greaterThan(
        await ethers.provider.getBalance(client.address)
      );
    });
  });

  describe("ZK-TaskFidelity Primitive Verification", function () {
    it("Should verify proof structure matches circuit output", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const proof = await generateValidProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      const publicSignals = [
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP,
      ];

      const isValid = await verifier.verifyProof(proof, publicSignals);
      expect(isValid).to.be.true;
    });

    it("Should reject proof with corrupted public signals", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const proof = await generateValidProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      const corruptedSignals = [
        "0x" + "0".repeat(64),
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP,
      ];

      const isValid = await verifier.verifyProof(proof, corruptedSignals);
      expect(isValid).to.be.false;
    });

    it("Should enforce cryptographic binding between proof and public signals", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const proof = await generateValidProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      const mismatchedSignals = [
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP + 1,
      ];

      await expect(
        market
          .connect(agent)
          .submitProof(taskId, proof, mismatchedSignals)
      ).to.be.revertedWith("ZK proof verification failed");
    });
  });

  describe("Gas Optimization & Economic Security", function () {
    it("Should complete task within reasonable gas limits", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const proof = await generateValidProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      const tx = await market
        .connect(agent)
        .submitProof(taskId, proof, [
          TEST_INPUT_HASH,
          TEST_OUTPUT_HASH,
          SLA_THRESHOLD,
          TEST_TIMESTAMP,
        ]);

      const receipt = await tx.wait();
      expect(receipt?.gasUsed).to.be.lessThan(500000);
    });

    it("Should prevent gas griefing via repeated invalid proof submissions", async function () {
      const taskId = ethers.randomBytes(32);
      const inputHash = ethers.keccak256(ethers.toUtf8Bytes(TASK_INPUT_DATA));

      await market
        .connect(client)
        .postTask(taskId, inputHash, REWARD_AMOUNT, SLA_THRESHOLD, {
          value: REWARD_AMOUNT,
        });

      const invalidProof = await generateMaliciousProof(
        TEST_INPUT_HASH,
        TEST_OUTPUT_HASH,
        SLA_THRESHOLD,
        TEST_TIMESTAMP
      );

      for (let i = 0; i < 3; i++) {
        await expect(
          market
            .connect(agent)
            .submitProof(taskId, invalidProof, [
              TEST_INPUT_HASH,
              TEST_OUTPUT_HASH,
              SLA_THRESHOLD,
              TEST_TIMESTAMP,
            ])
        ).to.be.revertedWith("ZK proof verification failed");
      }
    });
  });

  async function generateValidProof(
    inputHash: string,
    outputHash: string,
    slaThreshold: number,
    timestamp: number
  ) {
    const input = {
      input_data: Array.from(ethers.toUtf8Bytes(TASK_INPUT_DATA)).slice(0, 32),
      output_data: Array.from(ethers.toUtf8Bytes(TASK_OUTPUT_DATA)).slice(0, 32),
      computation_hash: Array.from(ethers.toUtf8Bytes("computation_123")).slice(
        0,
        32
      ),
      logic_signature: Array.from(ethers.toUtf8Bytes("logic_sig_456")).slice(
        0,
        32
      ),
    };

    const { proof, publicSignals } = await snarkjs.groth16.fullProve(
      input,
      CIRCUIT_PATH + ".wasm",
      ZKEY_PATH
    );

    return {
      A: proof.pi_a,
      B: proof.pi_b,
      C: proof.pi_c,
    };
  }

  async function generateMaliciousProof(
    inputHash: string,
    outputHash: string,
    slaThreshold: number,
    timestamp: number
  ) {
    const maliciousInput = {
      input_data: Array.from(ethers.toUtf8Bytes("malicious_data")).slice(0, 32),
      output_data: Array.from(ethers.toUtf8Bytes("malicious_output")).slice(0, 32),
      computation_hash: Array.from(ethers.toUtf8Bytes("malicious_comp")).slice(
        0,
        32
      ),
      logic_signature: Array.from(ethers.toUtf8Bytes("malicious_sig")).slice(
        0,
        32
      ),
    };

    try {
      const { proof } = await snarkjs.groth16.fullProve(
        maliciousInput,
        CIRCUIT_PATH + ".wasm",
        ZKEY_PATH
      );

      return {
        A: proof.pi_a,
        B: proof.pi_b,
        C: proof.pi_c,
      };
    } catch (error) {
      return {
        A: [0, 0, 0, 0, 0, 0, 0, 0],
        B: [[0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0], [0, 0]],
        C: [0, 0, 0, 0, 0, 0, 0, 0],
      };
    }
  }
});