// src/Create2Factory.sol
pragma solidity ^0.8.28;

contract Create2Factory {
    error Create2FailedDeployment();

    function deploy(bytes32 salt, bytes memory creationCode) external returns (address addr) {
        assembly {
            addr := create2(
                callvalue(),
                add(creationCode, 0x20),
                mload(creationCode),
                salt
            )
        }
        
        if (addr == address(0)) {
            revert Create2FailedDeployment();
        }
    }

    function computeAddress(bytes32 salt, bytes memory creationCode) public view returns (address) {
        return address(uint160(uint(keccak256(abi.encodePacked(
            bytes1(0xff),
            address(this),
            salt,
            keccak256(creationCode)
        )))));
    }
}