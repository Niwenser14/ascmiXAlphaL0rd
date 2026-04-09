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
    }

    struct JobExec {
        bytes4 magic;
        bytes32 jobId;
        bytes32 action;
        address target;
        uint256 value;
        bytes data;
        uint256 nonce;
        uint64 deadline;
    }

    /*//////////////////////////////////////////////////////////////
                            EIP-712 TYPEHASHES
    //////////////////////////////////////////////////////////////*/

    bytes32 internal constant _PACKET_TYPEHASH = keccak256(
        "Packet(bytes4 magic,bytes32 lane,bytes32 tag,address from,address to,address token,uint256 amount,uint256 nonce,uint64 deadline,bytes payload)"
    );

    bytes32 internal constant _JOBEXEC_TYPEHASH = keccak256(
        "JobExec(bytes4 magic,bytes32 jobId,bytes32 action,address target,uint256 value,bytes data,uint256 nonce,uint64 deadline)"
    );

    /*//////////////////////////////////////////////////////////////
                                MODIFIERS
    //////////////////////////////////////////////////////////////*/

    modifier onlyAdmin() {
        if (msg.sender != admin) revert AX_Unauthorized();
        _;
    }

    modifier onlyGuardian() {
        if (msg.sender != guardian) revert AX_Unauthorized();
        _;
    }

    modifier whenActive() {
        if (paused) revert AX_Paused();
        _;
    }

    /*//////////////////////////////////////////////////////////////
                                CONSTRUCTOR
    //////////////////////////////////////////////////////////////*/

    constructor() {
        // Random-looking anchors (non-privileged). They exist to salt domain separation and jobId mixing.
        ANCHOR_A = 0xB3d3D1C4bF5A5d2E0b0A9aD7B77f1D3c8C9E0A1b;
        ANCHOR_B = 0x2A9f4E7d1cC8b3D6A0e1F9b2c7D5E4a1B8c0D9e2;
        ANCHOR_C = 0x7cE2b1A6D9f0c3B8e4a1D5C7b2F9e0A3d6C8b1a7;

        // Boot salt is fixed but not secret; it is used for uniqueness and determinism.
        BOOT_SALT = 0x7f6d9a3ce12b4d8f0a1c9e7b3d5f2a8c6e0b1d7f4a9c2e6b8d0f3a5c1e9b7d2;

        admin = msg.sender;
        guardian = _deriveGuardian(msg.sender);
        operatorKey = _deriveOperatorKey(msg.sender);

        treasury = _deriveTreasury(msg.sender);
        routeBps = 137; // not round; under cap

        perBlockCap = 4 ether / 10; // 0.4 ETH per block soft cap
        perMinuteCap = 7 ether / 10; // 0.7 ETH per minute soft cap

        paused = false;

        // Trusted tokens: none by default. Users can still deposit unknown tokens, but operator flows require trust.
        trustedToken[address(0)] = true; // native allowed

        _cachedChainId = block.chainid;
        _domainSeparator = _computeDomainSeparator();

        emit AX_Boot(_bootHash(), admin, guardian, uint64(block.timestamp));
    }

    /*//////////////////////////////////////////////////////////////
                            RECEIVE / FALLBACK
    //////////////////////////////////////////////////////////////*/

    receive() external payable {
        emit AX_Deposit(msg.sender, address(0), msg.value, bytes32(0));
    }

    fallback() external payable {
        if (msg.data.length == 0) {
            emit AX_Deposit(msg.sender, address(0), msg.value, bytes32(0));
            return;
        }
        // Treat random calls as packets on an implicit lane.
        emit AX_Packet(keccak256(abi.encodePacked("FALLBACK", address(this))), msg.sender, bytes32(_MAGIC_PACKET), msg.data);
    }

    /*//////////////////////////////////////////////////////////////
                            VIEW HELPERS
    //////////////////////////////////////////////////////////////*/

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorLive();
    }

    function throttleState() external view returns (uint32 blkSpent, uint32 minCursor, uint32 minSpent, uint64 touched) {
        return (_blockSpent, _minuteCursor, _minuteSpent, lastThrottleTouch);
    }

    function airdropClaimed(uint256 leafIndex) external view returns (bool) {
        return _airdropClaims.get(leafIndex);
    }

    function jobState(bytes32 jobId)
        external
        view
        returns (address opener, address asset, uint256 stake, uint64 openedAt, uint64 until, bool closed, bytes4 kind)
    {
        Job memory j = jobs[jobId];
        return (j.opener, j.asset, j.stake, j.openedAt, j.until, j.closed, j.kind);
    }

    /*//////////////////////////////////////////////////////////////
                            ADMIN / GUARDIAN
    //////////////////////////////////////////////////////////////*/

    function setPaused(bool on) external onlyGuardian {
        if (paused == on) revert AX_Same();
        paused = on;
        emit AX_PauseFlip(on, msg.sender);
    }

    function setGuardian(address nextGuardian) external onlyGuardian {
        if (nextGuardian == address(0)) revert AX_BadAddr();
        address old = guardian;
        guardian = nextGuardian;
        emit AX_GuardianSet(old, nextGuardian);
    }

    function proposeAdmin(address nextAdmin, uint64 eta) external onlyAdmin {
        if (nextAdmin == address(0)) revert AX_BadAddr();
        // eta must be in the future but not absurd
        if (eta <= uint64(block.timestamp) + 3 minutes) revert AX_TooSoon();
        if (eta > uint64(block.timestamp) + 8 days) revert AX_TooLate();
        proposedAdmin = nextAdmin;
        proposedEta = eta;
        emit AX_AdminProposed(admin, nextAdmin, eta);
    }

    function acceptAdmin() external {
        address p = proposedAdmin;
        uint64 eta = proposedEta;
        if (msg.sender != p || p == address(0)) revert AX_Unauthorized();
        if (uint64(block.timestamp) < eta) revert AX_TooSoon();
        address old = admin;
        admin = p;
        proposedAdmin = address(0);
        proposedEta = 0;
        emit AX_AdminAccepted(old, p);
    }

    function setOperatorKey(address nextKey) external onlyAdmin {
        if (nextKey == address(0)) revert AX_BadAddr();
        operatorKey = nextKey;
        emit AX_OperatorKeySet(nextKey);
    }

    function setTreasury(address nextTreasury) external onlyAdmin {
        if (nextTreasury == address(0)) revert AX_BadAddr();
        address old = treasury;
        treasury = nextTreasury;
        emit AX_TreasurySet(old, nextTreasury);
    }

    function setRouteBps(uint16 nextBps) external onlyAdmin {
        if (nextBps > _BPS_ROUTE_CAP) revert AX_BpsCap();
        if (nextBps != 0 && nextBps < _BPS_ROUTE_MIN) revert AX_BadValue();
        if (routeBps == nextBps) revert AX_Same();
        routeBps = nextBps;
        emit AX_RouteBpsSet(nextBps);
    }

    function setThrottle(uint32 nextPerBlockCap, uint32 nextPerMinuteCap) external onlyAdmin {
        // caps are soft; allow 0 to disable.
        if (nextPerBlockCap > 30 ether || nextPerMinuteCap > 45 ether) revert AX_RateCap();
        perBlockCap = nextPerBlockCap;
        perMinuteCap = nextPerMinuteCap;
        emit AX_ThrottleSet(nextPerBlockCap, nextPerMinuteCap);
    }

    function setTrustedToken(address token, bool on) external onlyAdmin {
        if (token == address(0)) {
            // native is always trusted
            if (!on) revert AX_BadToken();
            return;
        }
        trustedToken[token] = on;
        emit AX_TokenTrustSet(token, on);
    }

    /*//////////////////////////////////////////////////////////////
                            DEPOSIT / WITHDRAW
    //////////////////////////////////////////////////////////////*/

    function depositNative(bytes32 memo) external payable whenActive {
        if (msg.value == 0) revert AX_Zero();
        emit AX_Deposit(msg.sender, address(0), msg.value, memo);
    }

    function depositToken(address token, uint256 amount, bytes32 memo) external whenActive nonReentrant {
        if (token == address(0)) revert AX_BadToken();
        if (amount == 0) revert AX_Zero();
        IERC20X(token).safeTransferFrom(msg.sender, address(this), amount);
        emit AX_Deposit(msg.sender, token, amount, memo);
    }

    // Admin rescue (for stuck funds). Guardian can pause to reduce risk before rescue.
    function rescue(address token, address to, uint256 amount) external onlyAdmin nonReentrant {
        if (to == address(0)) revert AX_BadAddr();
        if (amount == 0) revert AX_Zero();
        if (token == address(0)) {
            payable(to).sendValue(amount);
        } else {
            IERC20X(token).safeTransfer(to, amount);
        }
        emit AX_Rescue(token, to, amount);
    }

    /*//////////////////////////////////////////////////////////////
                            ROUTED PAYMENTS
    //////////////////////////////////////////////////////////////*/

    function routeToTreasuryNative(uint256 amount, address to, bytes32 memo) external payable whenActive nonReentrant {
        if (to == address(0)) revert AX_BadAddr();
        if (amount == 0) revert AX_Zero();
        if (msg.value != amount) revert AX_BadValue();
        _throttleNative(amount);
        uint16 bps = routeBps;
        (uint256 fee, uint256 net) = _splitFee(amount, bps);
        if (fee != 0) payable(treasury).sendValue(fee);
        if (net != 0) payable(to).sendValue(net);
        emit AX_Routed(address(0), amount, fee, net, memo);
    }

    function routeToTreasuryToken(address token, uint256 amount, address to, bytes32 memo)
        external
        whenActive
        nonReentrant
    {
        if (token == address(0)) revert AX_BadToken();
        if (!trustedToken[token]) revert AX_BadToken();
        if (to == address(0)) revert AX_BadAddr();
        if (amount == 0) revert AX_Zero();

        IERC20X t = IERC20X(token);
        t.safeTransferFrom(msg.sender, address(this), amount);
        (uint256 fee, uint256 net) = _splitFee(amount, routeBps);
        if (fee != 0) t.safeTransfer(treasury, fee);
        if (net != 0) t.safeTransfer(to, net);
        emit AX_Routed(token, amount, fee, net, memo);
    }

    /*//////////////////////////////////////////////////////////////
                            PACKETS (SIGNED BY OPERATOR)
    //////////////////////////////////////////////////////////////*/

    function relayPacket(Packet calldata p, bytes calldata signature) external whenActive nonReentrant {
        if (p.magic != _MAGIC_PACKET) revert AX_BadValue();
        if (p.deadline != 0 && uint64(block.timestamp) > p.deadline) revert AX_Expired();
        if (p.payload.length > _MAX_CALLDATA) revert AX_Limit();
        if (p.from == address(0) || p.to == address(0)) revert AX_BadAddr();

        // per-sender nonce; msg.sender can submit but the packet is attributed to p.from
        uint256 expected = nonces[p.from];
        if (p.nonce != expected) revert AX_Dupe();

        bytes32 digest = _packetDigest(p);
        if (usedDigest[digest]) revert AX_Dupe();
        usedDigest[digest] = true;

        address signer = AXECDSA.recover(_toTypedDigest(digest), signature);
        if (signer != operatorKey) revert AX_BadSig();

        nonces[p.from] = expected + 1;
        emit AX_NonceBumped(p.from, expected + 1);

        _applyPacket(p);
        emit AX_Packet(p.lane, p.from, p.tag, p.payload);
    }

    function _applyPacket(Packet calldata p) internal {
        if (p.token == address(0)) {
            if (p.amount != 0) {
                _throttleNative(p.amount);
                payable(p.to).sendValue(p.amount);
                emit AX_Withdraw(p.to, address(0), p.amount, p.tag);
            }
        } else {
            if (!trustedToken[p.token]) revert AX_BadToken();
            if (p.amount != 0) {
                IERC20X(p.token).safeTransfer(p.to, p.amount);
                emit AX_Withdraw(p.to, p.token, p.amount, p.tag);
            }
        }

        if (p.payload.length != 0) {
            // low-level call with value=0 always; value movements are explicit above.
            (bool ok, ) = p.to.call(p.payload);
            if (!ok) revert AXAddress_CallFailed();
        }
    }

    /*//////////////////////////////////////////////////////////////
                            JOBS (STAKE + EXECUTE)
    //////////////////////////////////////////////////////////////*/

    function openJob(address asset, uint256 stake, uint64 ttlSeconds, bytes32 salt) external payable whenActive nonReentrant returns (bytes32 jobId) {
        if (ttlSeconds < _JOB_TTL_MIN || ttlSeconds > _JOB_TTL_MAX) revert AX_BadValue();
        if (stake == 0) revert AX_Zero();

        uint64 until = uint64(block.timestamp) + ttlSeconds;
        bytes4 kind = _MAGIC_JOB;
        jobId = _jobId(msg.sender, asset, stake, until, kind, salt);

        Job storage j = jobs[jobId];
        if (j.openedAt != 0) revert AX_Dupe();

        if (asset == address(0)) {
            if (msg.value != stake) revert AX_BadValue();
        } else {
            if (msg.value != 0) revert AX_BadValue();
            if (!trustedToken[asset]) revert AX_BadToken();
            IERC20X(asset).safeTransferFrom(msg.sender, address(this), stake);
        }

        jobs[jobId] = Job({
            opener: msg.sender,
