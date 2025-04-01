// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
import "@openzeppelin/contracts/access/Ownable.sol";
import "@openzeppelin/contracts/security/Pausable.sol";

contract ClaimsContract is ReentrancyGuard, Ownable, Pausable {
    // Constants
    uint256 public constant PAYOUT_AMOUNT = 50 * 10**8; // 50 HBAR, 8 decimals (Hedera standard)
    
    // State
    mapping(address => bool) public policyHolders;
    uint256 public totalPayouts;
    
    // Events
    event PolicyHolderAdded(address indexed rider);
    event PayoutTriggered(address indexed rider, uint256 amount, uint256 timestamp);
    event FundsWithdrawn(address indexed to, uint256 amount);
    event FundsReceived(address indexed from, uint256 amount);

    // Constructor
    constructor() Ownable(msg.sender) {
        // Insurer is set as the owner via Ownable
    }

    // Add a policyholder (called when policy is issued)
    function addPolicyHolder(address rider) external onlyOwner whenNotPaused {
        require(rider != address(0), "Invalid rider address");
        require(!policyHolders[rider], "Rider already a policyholder");
        policyHolders[rider] = true;
        emit PolicyHolderAdded(rider);
    }

    // Trigger payout to a rider
    function triggerPayout(address rider) external onlyOwner nonReentrant whenNotPaused {
        require(rider != address(0), "Invalid rider address");
        require(policyHolders[rider], "Not a policyholder");
        require(address(this).balance >= PAYOUT_AMOUNT, "Insufficient contract balance");

        policyHolders[rider] = false; // One-time payout
        totalPayouts += PAYOUT_AMOUNT;

        (bool sent, ) = rider.call{value: PAYOUT_AMOUNT}("");
        require(sent, "Payout failed");

        emit PayoutTriggered(rider, PAYOUT_AMOUNT, block.timestamp);
    }

    // Get contract balance
    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    // Withdraw excess funds (for insurer)
    function withdrawFunds(uint256 amount) external onlyOwner nonReentrant {
        require(amount > 0, "Amount must be greater than zero");
        require(address(this).balance >= amount, "Insufficient balance");
        (bool sent, ) = msg.sender.call{value: amount}("");
        require(sent, "Withdrawal failed");
        emit FundsWithdrawn(msg.sender, amount);
    }

    // Emergency pause
    function pause() external onlyOwner {
        _pause();
    }

    // Resume operations
    function unpause() external onlyOwner {
        _unpause();
    }

    // Receive HBAR
    receive() external payable {
        emit FundsReceived(msg.sender, msg.value);
    }

    // Fallback function (just in case)
    fallback() external payable {
        emit FundsReceived(msg.sender, msg.value);
    }
}