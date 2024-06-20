// // SPDX-License-Identifier: MIT
// pragma solidity ^0.8.17;

// import { Script, console2 } from "forge-std/Script.sol";
// import { Counterfacts } from "../src/Counterfacts.sol";
// // import { BaseCreate2Script } from
// "create2-scripts/BaseCreate2Script.s.sol";

// contract Deploy is /*BaseCreate2Script*/ {
//     function run() public {
//         setUp();
//         string[] memory networks = vm.envString("NETWORKS", ",");
//         for (uint256 i; i < networks.length; i++) {
//             string memory network = networks[i];
//             vm.createSelectFork(getChain(network).rpcUrl);
//             address facts = _immutableCreate2IfNotDeployed(
//                 deployer,
//                 0x00000000000000000000000000000000000000001d37bcb7d710043fdf64a216,
//                 type(Counterfacts).creationCode
//             );
//             console2.log("Deployed Counterfacts to", facts);
//         }
//     }
// }
