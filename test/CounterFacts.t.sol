// SPDX-License-Identifier: MIT
pragma solidity ^0.8.17;

import { BaseTest } from "./BaseTest.sol";
import { ERC721 } from "solady/tokens/ERC721.sol";
import { console2 } from "forge-std/Test.sol";
import { TestCounterfacts } from "./helpers/TestCounterfacts.sol";
import { CounterFacts } from "../src/CounterFacts.sol";
import { LibString } from "solady/utils/LibString.sol";
import { Base64 } from "solady/utils/Base64.sol";
import { ConstructorMinter } from "./helpers/ConstructorMinter.sol";
import { Base64 } from "solady/utils/Base64.sol";

contract CounterfactsTest is BaseTest {
    TestCounterfacts counter;

    event MetadataUpdate(uint256 _tokenId);

    struct RevealedMetadata {
        string animation_url;
        Attribute[] attributes;
    }

    function setUp() public virtual override {
        super.setUp();
        vm.warp(1_696_961_599);
        counter = new TestCounterfacts();
    }

    function testMintPackUnpack(
        address creator,
        uint96 timestamp,
        address storageAddress
    ) public {
        creator = coerce(creator);
        vm.warp(timestamp);
        vm.prank(creator);
        bytes32 validationHash =
            keccak256(abi.encodePacked(creator, storageAddress));
        uint256 tokenId = counter.mint(storageAddress);
        (address _creator, uint256 _timestamp, bytes32 _validation) =
            counter.mintMetadata(tokenId);
        assertEq(_creator, creator, "creator != creator");
        assertEq(_timestamp, timestamp, "timestamp != timestamp");
        assertEq(_validation, validationHash, "validation != validationHash");
        assertEq(counter.ownerOf(tokenId), creator);
    }

    function testGetTokenSVG() public {
        uint256 tokenId = counter.mint(address(uint160(1234)));
        assertEq(counter.ownerOf(tokenId), address(this));
        string memory svg = counter.getTokenSVG(tokenId);
        vm.writeFile("x.svg", svg);

        string memory data =
            "this is a really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really really long string";
        address predicted = counter.predict(data, address(this), 0);
        tokenId = counter.mint(predicted);
        vm.warp(block.timestamp + 120);

        counter.reveal(tokenId, data, 0);
        svg = counter.getTokenSVG(tokenId);
        vm.writeFile("y.svg", svg);
    }

    // function testMint() public {
    //     uint256 tokenId = counter.mint(bytes32(uint256(1234)));
    //     assertEq(counter.ownerOf(tokenId), address(this));

    //     assertEq(counter.getDataContract(tokenId).dataContract,
    // address(1234));
    //     assertFalse(counter.getDataContract(tokenId).deployed); //,
    //         // address(1234));
    //     assertEq(counter.dataContractToTokenId(address(1234)), tokenId);

    //     uint256 nextTokenId = counter.mint(address(5678));
    //     assertEq(counter.ownerOf(nextTokenId), address(this));
    //     assertEq(
    //         counter.getDataContract(nextTokenId).dataContract, address(5678)
    //     );
    //     assertFalse(counter.getDataContract(nextTokenId).deployed); //,
    //         // address(5678));
    //     assertEq(counter.dataContractToTokenId(address(5678)), nextTokenId);
    //     assertTrue(tokenId != nextTokenId);
    // }

    // function testMint_ContractExists() public {
    //     vm.expectRevert(Counterfacts.ContractExists.selector);
    //     counter.mint(address(this));
    // }

    // function testMint_DuplicateCounterfact() public {
    //     counter.mint(address(1234));
    //     vm.expectRevert(Counterfacts.DuplicateCounterfact.selector);
    //     counter.mint(address(1234));
    // }

    function testReveal() public {
        address predicted = counter.predict("data", address(this), 0);
        uint256 tokenId = counter.mint(predicted);
        vm.warp(block.timestamp + 60);
        vm.expectEmit(true, false, false, false, address(counter));
        emit MetadataUpdate(tokenId);
        counter.reveal(tokenId, "data", 0);
    }

    function testReveal_TokenDoesNotExist() public {
        vm.expectRevert(
            abi.encodeWithSelector(ERC721.TokenDoesNotExist.selector)
        );
        counter.reveal(1, "data", 0);
    }

    function testReveal_IncorrectStorageAddress() public {
        uint256 tokenId = counter.mint(address(uint160(0)));
        vm.warp(block.timestamp + 60);
        vm.expectRevert(CounterFacts.IncorrectStorageAddress.selector);
        counter.reveal(tokenId, "data", 0);
    }

    function testReveal_InsufficientTimePassed() public {
        address predicted = counter.predict("data", address(this), 0);
        uint256 tokenId = counter.mint(predicted);
        vm.expectRevert(CounterFacts.InsufficientTimePassed.selector);
        counter.reveal(tokenId, "data", 0);
    }

    function testPredictDifferentCreator() public {
        address predicted = counter.predict("data", address(this), 0);
        address predicted2 = counter.predict("data", address(1234), 0);
        assertTrue(predicted != predicted2);
    }

    function testDataContractAddress() public {
        address predicted = counter.predict("data", address(this), 0);
        // mint
        uint256 tokenId = counter.mint(predicted);
        // warp
        vm.warp(block.timestamp + 60);
        // reveal
        counter.reveal(tokenId, "data", 0);
        assertEq(
            counter.dataContractAddress(tokenId),
            predicted,
            "dataContractAddress != predicted"
        );
    }

    function coerce(address addr) internal view returns (address) {
        return address(uint160(bound(uint160(addr), 1, type(uint160).max)));
    }

    function testDataContractAddress(address creator, uint96 salt) public {
        creator = coerce(creator);
        address predicted = counter.predict("data", creator, salt);
        // mint
        vm.prank(creator);
        uint256 tokenId = counter.mint(predicted);
        // warp
        vm.warp(block.timestamp + 60);
        // reveal
        counter.reveal(tokenId, "data", salt);
        assertEq(
            counter.dataContractAddress(tokenId),
            predicted,
            "dataContractAddress != predicted"
        );
    }

    function testStringURI_TokenDoesNotExist() public {
        vm.expectRevert(
            abi.encodeWithSelector(ERC721.TokenDoesNotExist.selector)
        );
        counter.tokenURI(1);
    }

    function scanFor(Attribute memory attr, Attribute[] memory attrs)
        internal
        pure
        returns (bool)
    {
        for (uint256 i = 0; i < attrs.length; i++) {
            Attribute memory compare = attrs[i];
            if (
                stringEq(attr.trait_type, compare.trait_type)
                    && stringEq(attr.value, attrs[i].value)
            ) {
                return true;
            }
        }
        return false;
    }

    function stringEq(string memory a, string memory b)
        internal
        pure
        returns (bool)
    {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }

    // function testStringURI2() public {
    //     string memory data = "";
    //     (address predicted, bytes32 validationHash) =
    //         getPredictedAndValidationHash(address(this), data, 0);

    //     // mint token
    //     uint256 tokenId = counter.mint(validationHash);
    //     // get json string
    //     vm.breakpoint("a");
    //     string memory stringUri = counter.stringURI(tokenId);
    //     // parse json into struct
    //     bytes memory jsonParsed = vm.parseJson(stringUri);
    //     vm.breakpoint("b");
    //     RevealedMetadata memory metadata =
    //         abi.decode(jsonParsed, (RevealedMetadata));
    //     // // check struct
    //     // assertEq(
    //     //     metadata.animation_url,
    //     //     string.concat(
    //     //         "data:text/plain,",
    //     //         "This Counterfact has not yet been revealed."
    //     //     )
    //     // );
    //     // assertTrue(
    //     //     scanFor(
    //     //         Attribute("Creator",
    // LibString.toHexString(address(this))),
    //     //         metadata.attributes
    //     //     )
    //     // );
    //     // assertTrue(
    //     //     scanFor(
    //     //         Attribute(
    //     //             "Validation Hash",
    //     //             LibString.toHexString(uint256(validationHash))
    //     //         ),
    //     //         metadata.attributes
    //     //     )
    //     // );
    //     // assertTrue(scanFor(Attribute("Revealed?", "No"),
    //     // metadata.attributes));

    //     // data = 'data "with quotes"';
    //     // (predicted, validationHash) =
    //     //     getPredictedAndValidationHash(address(this), data, 0);
    //     // tokenId = counter.mint(validationHash);
    //     // counter.reveal(tokenId, data, 0);
    //     // assertEq(
    //     //     counter.stringURI(tokenId),
    //     //     _generateString(data, address(this), predicted,
    // validationHash)
    //     // );
    //     // vm.parseJson
    // }

    function getPredictedAndValidationHash(
        address creator,
        string memory data,
        uint96 salt
    ) internal view returns (address, bytes32) {
        address predicted = counter.predict(data, creator, salt);
        bytes32 validationHash = keccak256(abi.encode(predicted, creator));
        return (predicted, validationHash);
    }

    // function testTokenURI() public {
    //     uint256 tokenId = counter.mint(address(1234));
    //     assertEq(
    //         counter.tokenURI(tokenId),
    //         _generateBase64("", address(this), address(1234))
    //     );

    //     string memory data = 'data "with quotes"';
    //     address predicted = counter.predict(data, bytes32(0));
    //     tokenId = counter.mint(predicted);
    //     counter.reveal(tokenId, data, bytes32(0));
    //     assertEq(
    //         counter.tokenURI(tokenId),
    //         _generateBase64(data, address(this), predicted)
    //     );
    // }

    // function _generateBase64(
    //     string memory data,
    //     address creator,
    //     address dataContract
    // ) internal pure returns (string memory) {
    //     return string.concat(
    //         "data:application/json;base64,",
    //         Base64.encode(bytes(_generateString(data, creator,
    // dataContract)))
    //     );
    // }

    function _generateString(
        string memory data,
        address creator,
        address dataContract,
        bytes32 validationHash
    ) internal pure returns (string memory) {
        if (bytes(data).length > 0) {
            data = LibString.concat(
                "data:text/plain,",
                LibString.escapeJSON(LibString.escapeHTML(data))
            );
        } else {
            data = LibString.concat(
                "data:text/plain,",
                "This Counterfact has not yet been revealed."
            );
        }
        string memory thing = string.concat(
            '{"animation_url":"',
            data,
            '","attributes":[{"trait_type":"Creator","value":"',
            LibString.toHexString(creator),
            '"},{"trait_type":"Data Contract","value":"',
            LibString.toHexString(dataContract),
            '"}]}'
        );
        if (dataContract != address(0)) {
            return string.concat(
                '{"animation_url":"',
                data,
                '","attributes":[{"trait_type":"Creator","value":"',
                LibString.toHexString(creator),
                '"},{"trait_type":"Data Contract","value":"',
                LibString.toHexString(dataContract),
                '"}]}'
            );
        }
    }

    struct Attribute {
        string trait_type;
        string value;
    }

    function testSimple() public {
        string memory jsonString =
            '{"trait_type":"Creator","value":" 0x28679A1a632125fbBf7A68d850E50623194A709E "}';
        bytes memory jsonBytes = vm.parseJson(jsonString);
        Attribute memory attr = abi.decode(jsonBytes, (Attribute));
        assertEq(attr.trait_type, "Creator");
        assertEq(attr.value, " 0x28679A1a632125fbBf7A68d850E50623194A709E ");
        jsonString =
            '[{"trait_type":"Creator","value":"hello"},{"trait_type":"Creator","value":"hello world"}]';
        jsonBytes = vm.parseJson(jsonString);
        Attribute[] memory attrs = abi.decode(jsonBytes, (Attribute[]));

        assertEq(attrs.length, 2);
        assertEq(attrs[0].trait_type, "Creator");
        assertEq(attrs[0].value, "hello");
        assertEq(attrs[1].trait_type, "Creator");
        assertEq(attrs[1].value, "hello world");
        // jsonString = string.concat(
        //     '{"animation_url":"hello","attributes":', jsonString, "}"
        // );
        // jsonBytes = vm.parseJson(jsonString);
        // RevealedMetadata memory metadata =
        //     abi.decode(jsonBytes, (RevealedMetadata));
    }

    function logAttr(Attribute memory attr) public {
        emit log_named_string("trait_type", attr.trait_type);
        emit log_named_string("value", attr.value);
    }
}
