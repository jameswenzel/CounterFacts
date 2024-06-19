// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import {Test} from "forge-std/Test.sol";
import {Corruptions} from "corruptions-font/Corruptions.sol";

contract BaseTest is Test {
    function setUp() public virtual { 
        vm.etch(Corruptions.CORRUPTIONS_POINTER, Corruptions.CORRUPTIONS)
    }
}
