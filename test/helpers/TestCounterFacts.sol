// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { CounterFacts } from "../../src/CounterFacts.sol";
import { SSTORE2 } from "solady/utils/SSTORE2.sol";

contract TestCounterfacts is CounterFacts {
    function setMetadata(
        uint256 tokenId,
        bytes32 validationHash,
        uint96 mintTime,
        address creator
    ) public {
        _setExtraData(tokenId, mintTime);
        _tokenMetadata[tokenId] =
            TokenMetadata({ creator: creator, validationHash: validationHash });
    }

    function setDataContract(uint256 tokenId, address data) public {
        _dataContractAddresses[tokenId] = data;
    }

    function getTokenSVG(uint256 tokenId) public view returns (string memory) {
        TokenMetadata memory metadata = _tokenMetadata[tokenId];
        address creator = metadata.creator;
        uint96 mintTime = _getExtraData(tokenId);
        bytes32 validationHash = metadata.validationHash;
        address dataContract = _dataContractAddresses[tokenId];

        string memory rawString = "This Counterfact has not yet been revealed.";
        if (dataContract != address(0)) {
            rawString = string(SSTORE2.read(dataContract));
        }

        return _tokenSVG({
            tokenId: tokenId,
            creator: creator,
            mintTime: mintTime,
            validationHash: validationHash,
            dataContract: dataContract,
            rawContent: rawString
        });
    }
}
