require("@nomicfoundation/hardhat-toolbox");

module.exports = {
  solidity: "0.8.0",
  paths: {
    sources: "./contracts", // Default, but explicit
    tests: "./test",
    cache: "./cache",
    artifacts: "./artifacts"
  },
  networks: {
    hardhat: {
      chainId: 1337,
      accounts: { count: 10 }
    }
  }
};