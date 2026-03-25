// SPDX-License-Identifier: MIT
pragma solidity ^0.7.0;

contract Token {
    mapping(address => uint256) public balances;

    function transfer(address to, uint256 amount) public {
        balances[msg.sender] -= amount;
        balances[to] += amount;
    }
}
