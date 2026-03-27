import { ethers } from "hardhat";

async function main() {
  console.log("🚀 Deploying ZK-Settle AgentLaborMarket Contract...");

  // Get deployer account
  const [deployer] = await ethers.getSigners();
  console.log("📍 Deploying with account:", deployer.address);
  console.log("💰 Balance:", ethers.formatEther(await deployer.getBalance()));

  // Deploy Verifier contract first
  console.log("\n🔐 Deploying Verifier.sol...");
  const Verifier = await ethers.getContractFactory("Verifier");
  const verifier = await Verifier.deploy();
  await verifier.waitForDeployment();
  const verifierAddress = await verifier.getAddress();
  console.log("✅ Verifier deployed at:", verifierAddress);

  // Deploy AgentLaborMarket contract
  console.log("\n🏗️  Deploying AgentLaborMarket.sol...");
  const AgentLaborMarket = await ethers.getContractFactory("AgentLaborMarket");
  const laborMarket = await AgentLaborMarket.deploy(verifierAddress);
  await laborMarket.waitForDeployment();
  const laborMarketAddress = await laborMarket.getAddress();
  console.log("✅ AgentLaborMarket deployed at:", laborMarketAddress);

  // Verify integration
  console.log("\n🔗 Verifying contract integration...");
  const deployedVerifier = await laborMarket.verifier();
  console.log("Verifier address in contract:", deployedVerifier);
  console.log("Verifier matches:", deployedVerifier === verifierAddress ? "✅ YES" : "❌ NO");

  // Display contract info
  console.log("\n📋 Contract Information:");
  console.log("========================================");
  console.log("AgentLaborMarket Address:", laborMarketAddress);
  console.log("Verifier Address:", verifierAddress);
  console.log("Deployer Address:", deployer.address);
  console.log("========================================");

  // Display function signatures
  console.log("\n📝 Contract Functions:");
  console.log("  - postTask(bytes32 inputHash, uint256 reward)");
  console.log("  - submitProof(bytes32 proof, bytes memory publicInputs)");
  console.log("  - releaseFunds()");
  console.log("  - getTask(bytes32 taskId) -> Task struct");
  console.log("  - isTaskCompleted(bytes32 taskId) -> bool");
  console.log("  - getTaskStatus(bytes32 taskId) -> TaskStatus enum");

  console.log("\n🎯 Protocol Primitive: ZK-TaskFidelity");
  console.log("  - ProveTaskFidelity: Agent B generates ZK proof of SLA compliance");
  console.log("  - VerifyTaskFidelity: On-chain proof verification");
  console.log("  - ReleaseFunds: Conditional fund release on proof validity");

  console.log("\n✅ Deployment Complete!");
  console.log("📝 Save these addresses for future interactions:");
  console.log("   AgentLaborMarket:", laborMarketAddress);
  console.log("   Verifier:", verifierAddress);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });