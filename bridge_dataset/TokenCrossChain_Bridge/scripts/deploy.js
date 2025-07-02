const { ethers } = require("hardhat");

async function main() {
  const [deployer] = await ethers.getSigners();

  // Deploy CustomToken contract
  const CustomToken = await ethers.getContractFactory("CustomToken");
  const customToken = await CustomToken.deploy();
  await customToken.deployed();
  console.log("CustomToken deployed to:", customToken.address);

  // Deploy CustomTokenL2 contract
  const CustomTokenL2 = await ethers.getContractFactory("CustomTokenL2");
  const customTokenL2 = await CustomTokenL2.deploy(deployer.address);
  await customTokenL2.deployed();
  console.log("CustomTokenL2 deployed to:", customTokenL2.address);

  // Deploy L1Bridge contract
  const L1Bridge = await ethers.getContractFactory("L1Bridge");
  const l1Bridge = await L1Bridge.deploy(customToken.address, deployer.address);
  await l1Bridge.deployed();
  console.log("L1Bridge deployed to:", l1Bridge.address);

  // Deploy L2Bridge contract
  const L2Bridge = await ethers.getContractFactory("L2Bridge");
  const l2Bridge = await L2Bridge.deploy(deployer.address);
  await l2Bridge.deployed();
  console.log("L2Bridge deployed to:", l2Bridge.address);
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error(error);
    process.exit(1);
  });
