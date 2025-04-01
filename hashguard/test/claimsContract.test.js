const { expect } = require("chai");
const { ethers } = require("hardhat");

describe("ClaimsContract", function () {
  let ClaimsContract, claimsContract, owner, rider;

  beforeEach(async function () {
    // Get signers (test accounts)
    [owner, rider] = await ethers.getSigners();

    // Deploy the contract
    ClaimsContract = await ethers.getContractFactory("ClaimsContract");
    claimsContract = await ClaimsContract.deploy();
    await claimsContract.deployed();

    // Fund the contract with 100 HBAR (simulated as ether)
    await owner.sendTransaction({
      to: claimsContract.address,
      value: ethers.utils.parseEther("100"),
    });
  });

  it("should set the owner correctly", async function () {
    expect(await claimsContract.owner()).to.equal(owner.address);
  });

  it("should have initial balance after funding", async function () {
    const balance = await claimsContract.getBalance();
    expect(balance).to.equal(ethers.utils.parseEther("100"));
  });

  it("should trigger payout to rider", async function () {
    const initialRiderBalance = await ethers.provider.getBalance(rider.address);
    const payoutAmount = ethers.utils.parseEther("50");

    // Trigger payout
    await claimsContract.connect(owner).triggerPayout(rider.address);

    // Check rider balance increased by 50 HBAR
    const finalRiderBalance = await ethers.provider.getBalance(rider.address);
    expect(finalRiderBalance.sub(initialRiderBalance)).to.equal(payoutAmount);

    // Check contract balance decreased by 50 HBAR
    const contractBalance = await claimsContract.getBalance();
    expect(contractBalance).to.equal(ethers.utils.parseEther("50"));

    // Check event emission
    await expect(claimsContract.connect(owner).triggerPayout(rider.address))
      .to.emit(claimsContract, "PayoutTriggered")
      .withArgs(rider.address, payoutAmount);
  });

  it("should fail if not owner triggers payout", async function () {
    await expect(
      claimsContract.connect(rider).triggerPayout(rider.address)
    ).to.be.revertedWith("Only owner can trigger payouts");
  });

  it("should fail if insufficient balance", async function () {
    // Deploy a new contract with no funds
    const newClaimsContract = await ClaimsContract.deploy();
    await newClaimsContract.deployed();

    await expect(
      newClaimsContract.connect(owner).triggerPayout(rider.address)
    ).to.be.revertedWith("Insufficient balance");
  });
});