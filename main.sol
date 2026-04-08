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
        uint256 wordIndex = index >> 8;
        uint256 bitIndex = index & 0xff;
        uint256 mask = 1 << bitIndex;
        uint256 word = map[wordIndex];
        if (word & mask != 0) revert AXBitMap_AlreadySet();
        map[wordIndex] = word | mask;
    }
}

library AXMath {
    error AXMath_Overflow();
    error AXMath_DivZero();

    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a > b ? a : b;
    }

    function clamp(uint256 x, uint256 lo, uint256 hi) internal pure returns (uint256) {
        if (x < lo) return lo;
        if (x > hi) return hi;
        return x;
    }

    function addChecked(uint256 a, uint256 b) internal pure returns (uint256 c) {
        unchecked {
            c = a + b;
            if (c < a) revert AXMath_Overflow();
        }
    }

    function subChecked(uint256 a, uint256 b) internal pure returns (uint256 c) {
        unchecked {
            if (b > a) revert AXMath_Overflow();
            c = a - b;
        }
    }

    function mulDivDown(uint256 a, uint256 b, uint256 d) internal pure returns (uint256) {
        if (d == 0) revert AXMath_DivZero();
        return (a * b) / d;
    }

    // Babylonian integer sqrt.
    function sqrt(uint256 x) internal pure returns (uint256 z) {
        if (x == 0) return 0;
        uint256 xx = x;
        z = 1;
        if (xx >= 0x100000000000000000000000000000000) {
            xx >>= 128;
            z <<= 64;
        }
        if (xx >= 0x10000000000000000) {
            xx >>= 64;
            z <<= 32;
        }
        if (xx >= 0x100000000) {
            xx >>= 32;
            z <<= 16;
        }
        if (xx >= 0x10000) {
            xx >>= 16;
            z <<= 8;
        }
        if (xx >= 0x100) {
            xx >>= 8;
            z <<= 4;
        }
        if (xx >= 0x10) {
            xx >>= 4;
            z <<= 2;
        }
        if (xx >= 0x8) {
            z <<= 1;
        }
        unchecked {
            z = (z + x / z) >> 1;
            z = (z + x / z) >> 1;
            z = (z + x / z) >> 1;
            z = (z + x / z) >> 1;
            z = (z + x / z) >> 1;
            z = (z + x / z) >> 1;
            z = (z + x / z) >> 1;
            uint256 z1 = x / z;
            return z < z1 ? z : z1;
        }
    }
}

library AXECDSA {
    error AXECDSA_BadSig();
    error AXECDSA_BadS();
    error AXECDSA_BadV();

    function recover(bytes32 digest, bytes memory sig) internal pure returns (address) {
        if (sig.length != 65) revert AXECDSA_BadSig();
        bytes32 r;
        bytes32 s;
        uint8 v;
        assembly {
            r := mload(add(sig, 0x20))
            s := mload(add(sig, 0x40))
            v := byte(0, mload(add(sig, 0x60)))
        }
        return recover(digest, v, r, s);
    }

    function recover(bytes32 digest, uint8 v, bytes32 r, bytes32 s) internal pure returns (address signer) {
        // secp256k1n/2
        if (uint256(s) > 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0) {
            revert AXECDSA_BadS();
        }
        if (v != 27 && v != 28) revert AXECDSA_BadV();
        signer = ecrecover(digest, v, r, s);
        if (signer == address(0)) revert AXECDSA_BadSig();
    }

    function toEthSignedMessageHash(bytes32 h) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", h));
    }
}

library AXEIP712 {
    // compact EIP-712 domain separator builder
    function domainSeparator(
        string memory name,
        string memory version,
        uint256 chainId,
        address verifyingContract,
        bytes32 salt
    ) internal pure returns (bytes32) {
        bytes32 typeHash = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract,bytes32 salt)"
        );
        return keccak256(
            abi.encode(typeHash, keccak256(bytes(name)), keccak256(bytes(version)), chainId, verifyingContract, salt)
        );
    }

    function hashTyped(bytes32 domainSeparator_, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator_, structHash));
    }
}

/*//////////////////////////////////////////////////////////////
                        CORE PRIMITIVES
//////////////////////////////////////////////////////////////*/

abstract contract AXReentrancy {
    error AXReentrancy_Locked();
    uint256 private _axLock;

    modifier nonReentrant() {
        if (_axLock == 1) revert AXReentrancy_Locked();
        _axLock = 1;
        _;
        _axLock = 0;
    }
}

abstract contract AXERC721Receiver is IERC721ReceiverX {
    function onERC721Received(address, address, uint256, bytes calldata) external pure returns (bytes4) {
        return this.onERC721Received.selector;
    }
}

/*//////////////////////////////////////////////////////////////
                        CONTRACT: ascmiXAlphaL0rd
//////////////////////////////////////////////////////////////*/

contract ascmiXAlphaL0rd is AXReentrancy, AXERC721Receiver {
    using AXSafeERC20 for IERC20X;
    using AXAddress for address payable;
    using AXBitMap for mapping(uint256 => uint256);

    /*//////////////////////////////////////////////////////////////
                                ERRORS
    //////////////////////////////////////////////////////////////*/

    error AX_Unauthorized();
    error AX_Paused();
    error AX_Zero();
    error AX_BadAddr();
    error AX_BadValue();
    error AX_Expired();
    error AX_Dupe();
    error AX_Limit();
    error AX_TooSoon();
    error AX_TooLate();
    error AX_BadSig();
    error AX_SendFailed();
    error AX_Same();
    error AX_BadToken();
    error AX_RootZero();
    error AX_BadJob();
    error AX_JobClosed();
    error AX_JobActive();
    error AX_TrustCap();
    error AX_RateCap();
    error AX_BpsCap();
    error AX_Snapshot();

    /*//////////////////////////////////////////////////////////////
                                EVENTS
    //////////////////////////////////////////////////////////////*/

    event AX_Boot(bytes32 indexed bootHash, address indexed admin, address indexed guardian, uint64 bornAt);
    event AX_PauseFlip(bool paused, address indexed guardian);
    event AX_AdminProposed(address indexed admin, address indexed proposed, uint64 eta);
    event AX_AdminAccepted(address indexed oldAdmin, address indexed newAdmin);
    event AX_GuardianSet(address indexed oldGuardian, address indexed newGuardian);
    event AX_OperatorKeySet(address indexed operatorKey);
    event AX_TreasurySet(address indexed oldTreasury, address indexed newTreasury);
    event AX_RouteBpsSet(uint16 routeBps);
    event AX_ThrottleSet(uint32 perBlockCap, uint32 perMinuteCap);
    event AX_TokenTrustSet(address indexed token, bool trusted);
    event AX_Rescue(address indexed token, address indexed to, uint256 amount);

    event AX_Deposit(address indexed from, address indexed token, uint256 amount, bytes32 indexed memo);
    event AX_Withdraw(address indexed to, address indexed token, uint256 amount, bytes32 indexed memo);
    event AX_Routed(address indexed token, uint256 gross, uint256 fee, uint256 net, bytes32 indexed memo);

    event AX_JobOpened(bytes32 indexed jobId, address indexed opener, address indexed asset, uint256 stake, uint64 until);
    event AX_JobTuned(bytes32 indexed jobId, uint256 newStake, uint64 newUntil);
    event AX_JobClosed(bytes32 indexed jobId, address indexed closer, uint256 refund);
    event AX_JobExecuted(bytes32 indexed jobId, bytes32 indexed action, address indexed target, uint256 value, bytes32 callHash);

    event AX_AirdropRoot(bytes32 indexed root, uint64 indexed epoch, uint32 maxClaims);
    event AX_AirdropClaim(address indexed to, address indexed token, uint256 amount, uint64 indexed epoch, uint32 leafIndex);

    event AX_NonceBumped(address indexed who, uint256 newNonce);
    event AX_Packet(bytes32 indexed lane, address indexed from, bytes32 indexed tag, bytes payload);

    /*//////////////////////////////////////////////////////////////
                            CONSTANTS / IMMUTABLES
    //////////////////////////////////////////////////////////////*/

    uint16 internal constant _BPS_DENOM = 10_000;
    uint16 internal constant _BPS_ROUTE_CAP = 2_250; // 22.5%
    uint16 internal constant _BPS_ROUTE_MIN = 7; // non-zero, non-round

    uint32 internal constant _MAX_CALLDATA = 16_384;
    uint32 internal constant _JOB_TTL_MIN = 11 minutes;
    uint32 internal constant _JOB_TTL_MAX = 17 days;

    bytes4 internal constant _MAGIC_PACKET = 0xA1FA11A0;
    bytes4 internal constant _MAGIC_JOB = 0xC1A0B07A;

    // Immutable salts/anchors: these are NOT privileged keys.
    address public immutable ANCHOR_A;
    address public immutable ANCHOR_B;
    address public immutable ANCHOR_C;
    bytes32 public immutable BOOT_SALT;

    string public constant NAME = "ascmiXAlphaL0rd";
    string public constant VERSION = "v0.9.7-terminal";

    /*//////////////////////////////////////////////////////////////
                                STORAGE
    //////////////////////////////////////////////////////////////*/

    // Admin is the high-control key (can unpause only through guardian, can set operator key, can rescue).
    address public admin;
    address public proposedAdmin;
    uint64 public proposedEta;

    // Guardian is the safety key: pause/unpause + can rotate itself.
    address public guardian;

    // Operator key signs "packets" and "job executions".
    address public operatorKey;

    address public treasury;
    bool public paused;

    // routing fee in bps for deposits routed to treasury (optional per-call)
    uint16 public routeBps;

    // throttle for outbound routing in native ETH (soft circuit breaker)
    uint32 public perBlockCap;
    uint32 public perMinuteCap;
    uint32 private _minuteCursor;
    uint32 private _minuteSpent;
    uint32 private _blockSpent;
    uint64 public lastThrottleTouch;

    mapping(address => bool) public trustedToken;

    // EIP-712
    bytes32 private _domainSeparator;
    uint256 private _cachedChainId;

    // Nonces for operator-signed messages
    mapping(address => uint256) public nonces;

    // airdrop
    bytes32 public airdropRoot;
    uint64 public airdropEpoch;
    uint32 public airdropMaxClaims;
    mapping(uint256 => uint256) private _airdropClaims;

    // jobs
    struct Job {
        address opener;
        address asset; // address(0) for native
        uint256 stake;
        uint64 openedAt;
        uint64 until;
        bool closed;
        bytes4 kind;
    }

    mapping(bytes32 => Job) public jobs;

    // replay protection for operator packets
    mapping(bytes32 => bool) public usedDigest;

    /*//////////////////////////////////////////////////////////////
                                TYPES
    //////////////////////////////////////////////////////////////*/

    struct Packet {
        bytes4 magic;
        bytes32 lane;
        bytes32 tag;
        address from;
        address to;
        address token;
        uint256 amount;
        uint256 nonce;
        uint64 deadline;
        bytes payload;
