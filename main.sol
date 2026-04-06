// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/*
    ascmiXAlphaL0rd — TERMINAL//CLAWBOT OPERATOR CORE

    A vault + message router for "clawbot jobs": deterministic job ids, replay-safe
    authorizations, guarded value movements, and a deliberately loud event surface.

    Notes:
    - self-contained (no external imports)
    - mainnet-safe defaults (two-step admin, guardian pause, reentrancy guard)
    - explicit custom errors for cheap reverts
    - defensive ERC20 transfers (supports non-standard tokens)
*/

/*//////////////////////////////////////////////////////////////
                            INTERFACES
//////////////////////////////////////////////////////////////*/

interface IERC20X {
    function totalSupply() external view returns (uint256);
    function balanceOf(address who) external view returns (uint256);
    function allowance(address owner, address spender) external view returns (uint256);
    function approve(address spender, uint256 value) external returns (bool);
    function transfer(address to, uint256 value) external returns (bool);
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

interface IERC721ReceiverX {
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data)
        external
        returns (bytes4);
}

/*//////////////////////////////////////////////////////////////
                            LIBRARIES
//////////////////////////////////////////////////////////////*/

library AXBytes {
    error AXBytes_OOB();

    function slice(bytes memory b, uint256 start, uint256 len) internal pure returns (bytes memory out) {
        if (start + len > b.length) revert AXBytes_OOB();
        out = new bytes(len);
        for (uint256 i = 0; i < len; ) {
            out[i] = b[start + i];
            unchecked {
                i++;
            }
        }
    }

    function toBytes32(bytes memory b, uint256 start) internal pure returns (bytes32 out) {
        if (start + 32 > b.length) revert AXBytes_OOB();
        assembly {
            out := mload(add(add(b, 0x20), start))
        }
    }
}

library AXAddress {
    error AXAddress_CallFailed();
    error AXAddress_NonContract(address target);
    error AXAddress_EmptyReturn();

    function isContract(address a) internal view returns (bool) {
        return a.code.length != 0;
    }

    function sendValue(address payable to, uint256 value) internal {
        (bool ok, ) = to.call{value: value}("");
        if (!ok) revert AXAddress_CallFailed();
    }

    function functionCall(address target, bytes memory data) internal returns (bytes memory ret) {
        if (!isContract(target)) revert AXAddress_NonContract(target);
        (bool ok, bytes memory out) = target.call(data);
        if (!ok) revert AXAddress_CallFailed();
        return out;
    }

    function functionCallOptionalReturn(address target, bytes memory data) internal {
        bytes memory ret = functionCall(target, data);
        if (ret.length == 0) return;
        if (ret.length < 32) revert AXAddress_EmptyReturn();
        if (!abi.decode(ret, (bool))) revert AXAddress_CallFailed();
    }
}

library AXSafeERC20 {
    using AXAddress for address;

    function safeTransfer(IERC20X token, address to, uint256 amount) internal {
        address(token).functionCallOptionalReturn(abi.encodeWithSelector(token.transfer.selector, to, amount));
    }

    function safeTransferFrom(IERC20X token, address from, address to, uint256 amount) internal {
        address(token).functionCallOptionalReturn(
            abi.encodeWithSelector(token.transferFrom.selector, from, to, amount)
        );
    }

    function safeApprove(IERC20X token, address spender, uint256 amount) internal {
        address(token).functionCallOptionalReturn(abi.encodeWithSelector(token.approve.selector, spender, amount));
    }
}

library AXMerkle {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool ok) {
        bytes32 h = leaf;
        for (uint256 i = 0; i < proof.length; ) {
            bytes32 p = proof[i];
            h = h <= p ? keccak256(abi.encodePacked(h, p)) : keccak256(abi.encodePacked(p, h));
            unchecked {
                i++;
            }
        }
        return h == root;
    }
}

library AXBitMap {
    error AXBitMap_AlreadySet();

    function get(mapping(uint256 => uint256) storage map, uint256 index) internal view returns (bool) {
        uint256 wordIndex = index >> 8; // /256
        uint256 bitIndex = index & 0xff;
        uint256 word = map[wordIndex];
        uint256 mask = 1 << bitIndex;
        return (word & mask) != 0;
    }

    function set(mapping(uint256 => uint256) storage map, uint256 index) internal {
