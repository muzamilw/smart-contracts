// Sources flattened with hardhat v2.12.4 https://hardhat.org

// File contracts/utils/Context.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/*
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */
abstract contract Context {
    function _msgSender() internal view virtual returns (address) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes calldata) {
        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}


// File contracts/utils/introspection/IERC165.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC165 standard, as defined in the
 * https://eips.ethereum.org/EIPS/eip-165[EIP].
 *
 * Implementers can declare support of contract interfaces, which can then be
 * queried by others ({ERC165Checker}).
 *
 * For an implementation, see {ERC165}.
 */
interface IERC165 {
    /**
     * @dev Returns true if this contract implements the interface defined by
     * `interfaceId`. See the corresponding
     * https://eips.ethereum.org/EIPS/eip-165#how-interfaces-are-identified[EIP section]
     * to learn more about how these ids are created.
     *
     * This function call must use less than 30 000 gas.
     */
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}


// File contracts/utils/introspection/ERC165.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Implementation of the {IERC165} interface.
 *
 * Contracts that want to implement ERC165 should inherit from this contract and override {supportsInterface} to check
 * for the additional interface id that will be supported. For example:
 *
 * ```solidity
 * function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
 *     return interfaceId == type(MyInterface).interfaceId || super.supportsInterface(interfaceId);
 * }
 * ```
 *
 * Alternatively, {ERC165Storage} provides an easier to use but more expensive implementation.
 */
abstract contract ERC165 is IERC165 {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IERC165).interfaceId;
    }
}


// File contracts/access/AccessControl.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev External interface of AccessControl declared to support ERC165 detection.
 */
interface IAccessControl {
    function hasRole(bytes32 role, address account) external view returns (bool);
    function getRoleAdmin(bytes32 role) external view returns (bytes32);
    function grantRole(bytes32 role, address account) external;
    function revokeRole(bytes32 role, address account) external;
    function renounceRole(bytes32 role, address account) external;
}

/**
 * @dev Contract module that allows children to implement role-based access
 * control mechanisms. This is a lightweight version that doesn't allow enumerating role
 * members except through off-chain means by accessing the contract event logs. Some
 * applications may benefit from on-chain enumerability, for those cases see
 * {AccessControlEnumerable}.
 *
 * Roles are referred to by their `bytes32` identifier. These should be exposed
 * in the external API and be unique. The best way to achieve this is by
 * using `public constant` hash digests:
 *
 * ```
 * bytes32 public constant MY_ROLE = keccak256("MY_ROLE");
 * ```
 *
 * Roles can be used to represent a set of permissions. To restrict access to a
 * function call, use {hasRole}:
 *
 * ```
 * function foo() public {
 *     require(hasRole(MY_ROLE, msg.sender));
 *     ...
 * }
 * ```
 *
 * Roles can be granted and revoked dynamically via the {grantRole} and
 * {revokeRole} functions. Each role has an associated admin role, and only
 * accounts that have a role's admin role can call {grantRole} and {revokeRole}.
 *
 * By default, the admin role for all roles is `DEFAULT_ADMIN_ROLE`, which means
 * that only accounts with this role will be able to grant or revoke other
 * roles. More complex role relationships can be created by using
 * {_setRoleAdmin}.
 *
 * WARNING: The `DEFAULT_ADMIN_ROLE` is also its own admin: it has permission to
 * grant and revoke this role. Extra precautions should be taken to secure
 * accounts that have been granted it.
 */
abstract contract AccessControl is Context, IAccessControl, ERC165 {
    struct RoleData {
        mapping (address => bool) members;
        bytes32 adminRole;
    }

    mapping (bytes32 => RoleData) private _roles;

    bytes32 public constant DEFAULT_ADMIN_ROLE = 0x00;

    /**
     * @dev Emitted when `newAdminRole` is set as ``role``'s admin role, replacing `previousAdminRole`
     *
     * `DEFAULT_ADMIN_ROLE` is the starting admin for all roles, despite
     * {RoleAdminChanged} not being emitted signaling this.
     *
     * _Available since v3.1._
     */
    event RoleAdminChanged(bytes32 indexed role, bytes32 indexed previousAdminRole, bytes32 indexed newAdminRole);

    /**
     * @dev Emitted when `account` is granted `role`.
     *
     * `sender` is the account that originated the contract call, an admin role
     * bearer except when using {_setupRole}.
     */
    event RoleGranted(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev Emitted when `account` is revoked `role`.
     *
     * `sender` is the account that originated the contract call:
     *   - if using `revokeRole`, it is the admin role bearer
     *   - if using `renounceRole`, it is the role bearer (i.e. `account`)
     */
    event RoleRevoked(bytes32 indexed role, address indexed account, address indexed sender);

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControl).interfaceId
            || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns `true` if `account` has been granted `role`.
     */
    function hasRole(bytes32 role, address account) public view override returns (bool) {
        return _roles[role].members[account];
    }

    /**
     * @dev Returns the admin role that controls `role`. See {grantRole} and
     * {revokeRole}.
     *
     * To change a role's admin, use {_setRoleAdmin}.
     */
    function getRoleAdmin(bytes32 role) public view override returns (bytes32) {
        return _roles[role].adminRole;
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function grantRole(bytes32 role, address account) public virtual override {
        require(hasRole(getRoleAdmin(role), _msgSender()), "AccessControl: sender must be an admin to grant");

        _grantRole(role, account);
    }

    /**
     * @dev Revokes `role` from `account`.
     *
     * If `account` had been granted `role`, emits a {RoleRevoked} event.
     *
     * Requirements:
     *
     * - the caller must have ``role``'s admin role.
     */
    function revokeRole(bytes32 role, address account) public virtual override {
        require(hasRole(getRoleAdmin(role), _msgSender()), "AccessControl: sender must be an admin to revoke");

        _revokeRole(role, account);
    }

    /**
     * @dev Revokes `role` from the calling account.
     *
     * Roles are often managed via {grantRole} and {revokeRole}: this function's
     * purpose is to provide a mechanism for accounts to lose their privileges
     * if they are compromised (such as when a trusted device is misplaced).
     *
     * If the calling account had been granted `role`, emits a {RoleRevoked}
     * event.
     *
     * Requirements:
     *
     * - the caller must be `account`.
     */
    function renounceRole(bytes32 role, address account) public virtual override {
        require(account == _msgSender(), "AccessControl: can only renounce roles for self");

        _revokeRole(role, account);
    }

    /**
     * @dev Grants `role` to `account`.
     *
     * If `account` had not been already granted `role`, emits a {RoleGranted}
     * event. Note that unlike {grantRole}, this function doesn't perform any
     * checks on the calling account.
     *
     * [WARNING]
     * ====
     * This function should only be called from the constructor when setting
     * up the initial roles for the system.
     *
     * Using this function in any other way is effectively circumventing the admin
     * system imposed by {AccessControl}.
     * ====
     */
    function _setupRole(bytes32 role, address account) internal virtual {
        _grantRole(role, account);
    }

    /**
     * @dev Sets `adminRole` as ``role``'s admin role.
     *
     * Emits a {RoleAdminChanged} event.
     */
    function _setRoleAdmin(bytes32 role, bytes32 adminRole) internal virtual {
        emit RoleAdminChanged(role, getRoleAdmin(role), adminRole);
        _roles[role].adminRole = adminRole;
    }

    function _grantRole(bytes32 role, address account) private {
        if (!hasRole(role, account)) {
            _roles[role].members[account] = true;
            emit RoleGranted(role, account, _msgSender());
        }
    }

    function _revokeRole(bytes32 role, address account) private {
        if (hasRole(role, account)) {
            _roles[role].members[account] = false;
            emit RoleRevoked(role, account, _msgSender());
        }
    }
}


// File contracts/utils/structs/EnumerableSet.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Library for managing
 * https://en.wikipedia.org/wiki/Set_(abstract_data_type)[sets] of primitive
 * types.
 *
 * Sets have the following properties:
 *
 * - Elements are added, removed, and checked for existence in constant time
 * (O(1)).
 * - Elements are enumerated in O(n). No guarantees are made on the ordering.
 *
 * ```
 * contract Example {
 *     // Add the library methods
 *     using EnumerableSet for EnumerableSet.AddressSet;
 *
 *     // Declare a set state variable
 *     EnumerableSet.AddressSet private mySet;
 * }
 * ```
 *
 * As of v3.3.0, sets of type `bytes32` (`Bytes32Set`), `address` (`AddressSet`)
 * and `uint256` (`UintSet`) are supported.
 */
library EnumerableSet {
    // To implement this library for multiple types with as little code
    // repetition as possible, we write it in terms of a generic Set type with
    // bytes32 values.
    // The Set implementation uses private functions, and user-facing
    // implementations (such as AddressSet) are just wrappers around the
    // underlying Set.
    // This means that we can only create new EnumerableSets for types that fit
    // in bytes32.

    struct Set {
        // Storage of set values
        bytes32[] _values;

        // Position of the value in the `values` array, plus 1 because index 0
        // means a value is not in the set.
        mapping (bytes32 => uint256) _indexes;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function _add(Set storage set, bytes32 value) private returns (bool) {
        if (!_contains(set, value)) {
            set._values.push(value);
            // The value is stored at length-1, but we add 1 to all indexes
            // and use 0 as a sentinel value
            set._indexes[value] = set._values.length;
            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function _remove(Set storage set, bytes32 value) private returns (bool) {
        // We read and store the value's index to prevent multiple reads from the same storage slot
        uint256 valueIndex = set._indexes[value];

        if (valueIndex != 0) { // Equivalent to contains(set, value)
            // To delete an element from the _values array in O(1), we swap the element to delete with the last one in
            // the array, and then remove the last element (sometimes called as 'swap and pop').
            // This modifies the order of the array, as noted in {at}.

            uint256 toDeleteIndex = valueIndex - 1;
            uint256 lastIndex = set._values.length - 1;

            // When the value to delete is the last one, the swap operation is unnecessary. However, since this occurs
            // so rarely, we still do the swap anyway to avoid the gas cost of adding an 'if' statement.

            bytes32 lastvalue = set._values[lastIndex];

            // Move the last value to the index where the value to delete is
            set._values[toDeleteIndex] = lastvalue;
            // Update the index for the moved value
            set._indexes[lastvalue] = toDeleteIndex + 1; // All indexes are 1-based

            // Delete the slot where the moved value was stored
            set._values.pop();

            // Delete the index for the deleted slot
            delete set._indexes[value];

            return true;
        } else {
            return false;
        }
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function _contains(Set storage set, bytes32 value) private view returns (bool) {
        return set._indexes[value] != 0;
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function _length(Set storage set) private view returns (uint256) {
        return set._values.length;
    }

   /**
    * @dev Returns the value stored at position `index` in the set. O(1).
    *
    * Note that there are no guarantees on the ordering of values inside the
    * array, and it may change when more values are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function _at(Set storage set, uint256 index) private view returns (bytes32) {
        require(set._values.length > index, "EnumerableSet: index out of bounds");
        return set._values[index];
    }

    // Bytes32Set

    struct Bytes32Set {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        return _add(set._inner, value);
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(Bytes32Set storage set, bytes32 value) internal returns (bool) {
        return _remove(set._inner, value);
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(Bytes32Set storage set, bytes32 value) internal view returns (bool) {
        return _contains(set._inner, value);
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(Bytes32Set storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

   /**
    * @dev Returns the value stored at position `index` in the set. O(1).
    *
    * Note that there are no guarantees on the ordering of values inside the
    * array, and it may change when more values are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function at(Bytes32Set storage set, uint256 index) internal view returns (bytes32) {
        return _at(set._inner, index);
    }

    // AddressSet

    struct AddressSet {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(AddressSet storage set, address value) internal returns (bool) {
        return _add(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(AddressSet storage set, address value) internal returns (bool) {
        return _remove(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(AddressSet storage set, address value) internal view returns (bool) {
        return _contains(set._inner, bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Returns the number of values in the set. O(1).
     */
    function length(AddressSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

   /**
    * @dev Returns the value stored at position `index` in the set. O(1).
    *
    * Note that there are no guarantees on the ordering of values inside the
    * array, and it may change when more values are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function at(AddressSet storage set, uint256 index) internal view returns (address) {
        return address(uint160(uint256(_at(set._inner, index))));
    }


    // UintSet

    struct UintSet {
        Set _inner;
    }

    /**
     * @dev Add a value to a set. O(1).
     *
     * Returns true if the value was added to the set, that is if it was not
     * already present.
     */
    function add(UintSet storage set, uint256 value) internal returns (bool) {
        return _add(set._inner, bytes32(value));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the value was removed from the set, that is if it was
     * present.
     */
    function remove(UintSet storage set, uint256 value) internal returns (bool) {
        return _remove(set._inner, bytes32(value));
    }

    /**
     * @dev Returns true if the value is in the set. O(1).
     */
    function contains(UintSet storage set, uint256 value) internal view returns (bool) {
        return _contains(set._inner, bytes32(value));
    }

    /**
     * @dev Returns the number of values on the set. O(1).
     */
    function length(UintSet storage set) internal view returns (uint256) {
        return _length(set._inner);
    }

   /**
    * @dev Returns the value stored at position `index` in the set. O(1).
    *
    * Note that there are no guarantees on the ordering of values inside the
    * array, and it may change when more values are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function at(UintSet storage set, uint256 index) internal view returns (uint256) {
        return uint256(_at(set._inner, index));
    }
}


// File contracts/access/AccessControlEnumerable.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev External interface of AccessControlEnumerable declared to support ERC165 detection.
 */
interface IAccessControlEnumerable {
    function getRoleMember(bytes32 role, uint256 index) external view returns (address);
    function getRoleMemberCount(bytes32 role) external view returns (uint256);
}

/**
 * @dev Extension of {AccessControl} that allows enumerating the members of each role.
 */
abstract contract AccessControlEnumerable is IAccessControlEnumerable, AccessControl {
    using EnumerableSet for EnumerableSet.AddressSet;

    mapping (bytes32 => EnumerableSet.AddressSet) private _roleMembers;

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return interfaceId == type(IAccessControlEnumerable).interfaceId
            || super.supportsInterface(interfaceId);
    }

    /**
     * @dev Returns one of the accounts that have `role`. `index` must be a
     * value between 0 and {getRoleMemberCount}, non-inclusive.
     *
     * Role bearers are not sorted in any particular way, and their ordering may
     * change at any point.
     *
     * WARNING: When using {getRoleMember} and {getRoleMemberCount}, make sure
     * you perform all queries on the same block. See the following
     * https://forum.openzeppelin.com/t/iterating-over-elements-on-enumerableset-in-openzeppelin-contracts/2296[forum post]
     * for more information.
     */
    function getRoleMember(bytes32 role, uint256 index) public view override returns (address) {
        return _roleMembers[role].at(index);
    }

    /**
     * @dev Returns the number of accounts that have `role`. Can be used
     * together with {getRoleMember} to enumerate all bearers of a role.
     */
    function getRoleMemberCount(bytes32 role) public view override returns (uint256) {
        return _roleMembers[role].length();
    }

    /**
     * @dev Overload {grantRole} to track enumerable memberships
     */
    function grantRole(bytes32 role, address account) public virtual override {
        super.grantRole(role, account);
        _roleMembers[role].add(account);
    }

    /**
     * @dev Overload {revokeRole} to track enumerable memberships
     */
    function revokeRole(bytes32 role, address account) public virtual override {
        super.revokeRole(role, account);
        _roleMembers[role].remove(account);
    }

    /**
     * @dev Overload {_setupRole} to track enumerable memberships
     */
    function _setupRole(bytes32 role, address account) internal virtual override {
        super._setupRole(role, account);
        _roleMembers[role].add(account);
    }
}


// File contracts/access/Ownable.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor () {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}


// File contracts/governance/TimelockController.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Contract module which acts as a timelocked controller. When set as the
 * owner of an `Ownable` smart contract, it enforces a timelock on all
 * `onlyOwner` maintenance operations. This gives time for users of the
 * controlled contract to exit before a potentially dangerous maintenance
 * operation is applied.
 *
 * By default, this contract is self administered, meaning administration tasks
 * have to go through the timelock process. The proposer (resp executor) role
 * is in charge of proposing (resp executing) operations. A common use case is
 * to position this {TimelockController} as the owner of a smart contract, with
 * a multisig or a DAO as the sole proposer.
 *
 * _Available since v3.3._
 */
contract TimelockController is AccessControl {
    bytes32 public constant TIMELOCK_ADMIN_ROLE = keccak256("TIMELOCK_ADMIN_ROLE");
    bytes32 public constant PROPOSER_ROLE = keccak256("PROPOSER_ROLE");
    bytes32 public constant EXECUTOR_ROLE = keccak256("EXECUTOR_ROLE");
    uint256 internal constant _DONE_TIMESTAMP = uint256(1);

    mapping(bytes32 => uint256) private _timestamps;
    uint256 private _minDelay;

    /**
     * @dev Emitted when a call is scheduled as part of operation `id`.
     */
    event CallScheduled(bytes32 indexed id, uint256 indexed index, address target, uint256 value, bytes data, bytes32 predecessor, uint256 delay);

    /**
     * @dev Emitted when a call is performed as part of operation `id`.
     */
    event CallExecuted(bytes32 indexed id, uint256 indexed index, address target, uint256 value, bytes data);

    /**
     * @dev Emitted when operation `id` is cancelled.
     */
    event Cancelled(bytes32 indexed id);

    /**
     * @dev Emitted when the minimum delay for future operations is modified.
     */
    event MinDelayChange(uint256 oldDuration, uint256 newDuration);

    /**
     * @dev Initializes the contract with a given `minDelay`.
     */
    constructor(uint256 minDelay, address[] memory proposers, address[] memory executors) {
        _setRoleAdmin(TIMELOCK_ADMIN_ROLE, TIMELOCK_ADMIN_ROLE);
        _setRoleAdmin(PROPOSER_ROLE, TIMELOCK_ADMIN_ROLE);
        _setRoleAdmin(EXECUTOR_ROLE, TIMELOCK_ADMIN_ROLE);

        // deployer + self administration
        _setupRole(TIMELOCK_ADMIN_ROLE, _msgSender());
        _setupRole(TIMELOCK_ADMIN_ROLE, address(this));

        // register proposers
        for (uint256 i = 0; i < proposers.length; ++i) {
            _setupRole(PROPOSER_ROLE, proposers[i]);
        }

        // register executors
        for (uint256 i = 0; i < executors.length; ++i) {
            _setupRole(EXECUTOR_ROLE, executors[i]);
        }

        _minDelay = minDelay;
        emit MinDelayChange(0, minDelay);
    }

    /**
     * @dev Modifier to make a function callable only by a certain role. In
     * addition to checking the sender's role, `address(0)` 's role is also
     * considered. Granting a role to `address(0)` is equivalent to enabling
     * this role for everyone.
     */
    modifier onlyRole(bytes32 role) {
        require(hasRole(role, _msgSender()) || hasRole(role, address(0)), "TimelockController: sender requires permission");
        _;
    }

    /**
     * @dev Contract might receive/hold ETH as part of the maintenance process.
     */
    receive() external payable {}

    /**
     * @dev Returns whether an id correspond to a registered operation. This
     * includes both Pending, Ready and Done operations.
     */
    function isOperation(bytes32 id) public view virtual returns (bool pending) {
        return getTimestamp(id) > 0;
    }

    /**
     * @dev Returns whether an operation is pending or not.
     */
    function isOperationPending(bytes32 id) public view virtual returns (bool pending) {
        return getTimestamp(id) > _DONE_TIMESTAMP;
    }

    /**
     * @dev Returns whether an operation is ready or not.
     */
    function isOperationReady(bytes32 id) public view virtual returns (bool ready) {
        uint256 timestamp = getTimestamp(id);
        // solhint-disable-next-line not-rely-on-time
        return timestamp > _DONE_TIMESTAMP && timestamp <= block.timestamp;
    }

    /**
     * @dev Returns whether an operation is done or not.
     */
    function isOperationDone(bytes32 id) public view virtual returns (bool done) {
        return getTimestamp(id) == _DONE_TIMESTAMP;
    }

    /**
     * @dev Returns the timestamp at with an operation becomes ready (0 for
     * unset operations, 1 for done operations).
     */
    function getTimestamp(bytes32 id) public view virtual returns (uint256 timestamp) {
        return _timestamps[id];
    }

    /**
     * @dev Returns the minimum delay for an operation to become valid.
     *
     * This value can be changed by executing an operation that calls `updateDelay`.
     */
    function getMinDelay() public view virtual returns (uint256 duration) {
        return _minDelay;
    }

    /**
     * @dev Returns the identifier of an operation containing a single
     * transaction.
     */
    function hashOperation(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt) public pure virtual returns (bytes32 hash) {
        return keccak256(abi.encode(target, value, data, predecessor, salt));
    }

    /**
     * @dev Returns the identifier of an operation containing a batch of
     * transactions.
     */
    function hashOperationBatch(address[] calldata targets, uint256[] calldata values, bytes[] calldata datas, bytes32 predecessor, bytes32 salt) public pure virtual returns (bytes32 hash) {
        return keccak256(abi.encode(targets, values, datas, predecessor, salt));
    }

    /**
     * @dev Schedule an operation containing a single transaction.
     *
     * Emits a {CallScheduled} event.
     *
     * Requirements:
     *
     * - the caller must have the 'proposer' role.
     */
    function schedule(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt, uint256 delay) public virtual onlyRole(PROPOSER_ROLE) {
        bytes32 id = hashOperation(target, value, data, predecessor, salt);
        _schedule(id, delay);
        emit CallScheduled(id, 0, target, value, data, predecessor, delay);
    }

    /**
     * @dev Schedule an operation containing a batch of transactions.
     *
     * Emits one {CallScheduled} event per transaction in the batch.
     *
     * Requirements:
     *
     * - the caller must have the 'proposer' role.
     */
    function scheduleBatch(address[] calldata targets, uint256[] calldata values, bytes[] calldata datas, bytes32 predecessor, bytes32 salt, uint256 delay) public virtual onlyRole(PROPOSER_ROLE) {
        require(targets.length == values.length, "TimelockController: length mismatch");
        require(targets.length == datas.length, "TimelockController: length mismatch");

        bytes32 id = hashOperationBatch(targets, values, datas, predecessor, salt);
        _schedule(id, delay);
        for (uint256 i = 0; i < targets.length; ++i) {
            emit CallScheduled(id, i, targets[i], values[i], datas[i], predecessor, delay);
        }
    }

    /**
     * @dev Schedule an operation that is to becomes valid after a given delay.
     */
    function _schedule(bytes32 id, uint256 delay) private {
        require(!isOperation(id), "TimelockController: operation already scheduled");
        require(delay >= getMinDelay(), "TimelockController: insufficient delay");
        // solhint-disable-next-line not-rely-on-time
        _timestamps[id] = block.timestamp + delay;
    }

    /**
     * @dev Cancel an operation.
     *
     * Requirements:
     *
     * - the caller must have the 'proposer' role.
     */
    function cancel(bytes32 id) public virtual onlyRole(PROPOSER_ROLE) {
        require(isOperationPending(id), "TimelockController: operation cannot be cancelled");
        delete _timestamps[id];

        emit Cancelled(id);
    }

    /**
     * @dev Execute an (ready) operation containing a single transaction.
     *
     * Emits a {CallExecuted} event.
     *
     * Requirements:
     *
     * - the caller must have the 'executor' role.
     */
    function execute(address target, uint256 value, bytes calldata data, bytes32 predecessor, bytes32 salt) public payable virtual onlyRole(EXECUTOR_ROLE) {
        bytes32 id = hashOperation(target, value, data, predecessor, salt);
        _beforeCall(predecessor);
        _call(id, 0, target, value, data);
        _afterCall(id);
    }

    /**
     * @dev Execute an (ready) operation containing a batch of transactions.
     *
     * Emits one {CallExecuted} event per transaction in the batch.
     *
     * Requirements:
     *
     * - the caller must have the 'executor' role.
     */
    function executeBatch(address[] calldata targets, uint256[] calldata values, bytes[] calldata datas, bytes32 predecessor, bytes32 salt) public payable virtual onlyRole(EXECUTOR_ROLE) {
        require(targets.length == values.length, "TimelockController: length mismatch");
        require(targets.length == datas.length, "TimelockController: length mismatch");

        bytes32 id = hashOperationBatch(targets, values, datas, predecessor, salt);
        _beforeCall(predecessor);
        for (uint256 i = 0; i < targets.length; ++i) {
            _call(id, i, targets[i], values[i], datas[i]);
        }
        _afterCall(id);
    }

    /**
     * @dev Checks before execution of an operation's calls.
     */
    function _beforeCall(bytes32 predecessor) private view {
        require(predecessor == bytes32(0) || isOperationDone(predecessor), "TimelockController: missing dependency");
    }

    /**
     * @dev Checks after execution of an operation's calls.
     */
    function _afterCall(bytes32 id) private {
        require(isOperationReady(id), "TimelockController: operation is not ready");
        _timestamps[id] = _DONE_TIMESTAMP;
    }

    /**
     * @dev Execute an operation's call.
     *
     * Emits a {CallExecuted} event.
     */
    function _call(bytes32 id, uint256 index, address target, uint256 value, bytes calldata data) private {
        // solhint-disable-next-line avoid-low-level-calls
        (bool success,) = target.call{value: value}(data);
        require(success, "TimelockController: underlying transaction reverted");

        emit CallExecuted(id, index, target, value, data);
    }

    /**
     * @dev Changes the minimum timelock duration for future operations.
     *
     * Emits a {MinDelayChange} event.
     *
     * Requirements:
     *
     * - the caller must be the timelock itself. This can only be achieved by scheduling and later executing
     * an operation where the timelock is the target and the data is the ABI-encoded call to this function.
     */
    function updateDelay(uint256 newDelay) external virtual {
        require(msg.sender == address(this), "TimelockController: caller must be timelock");
        emit MinDelayChange(_minDelay, newDelay);
        _minDelay = newDelay;
    }
}


// File contracts/metatx/ERC2771Context.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/*
 * @dev Context variant with ERC2771 support.
 */
abstract contract ERC2771Context is Context {
    address immutable _trustedForwarder;

    constructor(address trustedForwarder) {
        _trustedForwarder = trustedForwarder;
    }

    function isTrustedForwarder(address forwarder) public view virtual returns(bool) {
        return forwarder == _trustedForwarder;
    }

    function _msgSender() internal view virtual override returns (address sender) {
        if (isTrustedForwarder(msg.sender)) {
            // The assembly code is more direct than the Solidity version using `abi.decode`.
            assembly { sender := shr(96, calldataload(sub(calldatasize(), 20))) }
        } else {
            return super._msgSender();
        }
    }

    function _msgData() internal view virtual override returns (bytes calldata) {
        if (isTrustedForwarder(msg.sender)) {
            return msg.data[:msg.data.length-20];
        } else {
            return super._msgData();
        }
    }
}


// File contracts/utils/cryptography/ECDSA.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Elliptic Curve Digital Signature Algorithm (ECDSA) operations.
 *
 * These functions can be used to verify that a message was signed by the holder
 * of the private keys of a given address.
 */
library ECDSA {
    /**
     * @dev Returns the address that signed a hashed message (`hash`) with
     * `signature`. This address can then be used for verification purposes.
     *
     * The `ecrecover` EVM opcode allows for malleable (non-unique) signatures:
     * this function rejects them by requiring the `s` value to be in the lower
     * half order, and the `v` value to be either 27 or 28.
     *
     * IMPORTANT: `hash` _must_ be the result of a hash operation for the
     * verification to be secure: it is possible to craft signatures that
     * recover to arbitrary addresses for non-hashed data. A safe way to ensure
     * this is by receiving a hash of the original message (which may otherwise
     * be too long), and then calling {toEthSignedMessageHash} on it.
     */
    function recover(bytes32 hash, bytes memory signature) internal pure returns (address) {
        // Check the signature length
        if (signature.length != 65) {
            revert("ECDSA: invalid signature length");
        }

        // Divide the signature in r, s and v variables
        bytes32 r;
        bytes32 s;
        uint8 v;

        // ecrecover takes the signature parameters, and the only way to get them
        // currently is to use assembly.
        // solhint-disable-next-line no-inline-assembly
        assembly {
            r := mload(add(signature, 0x20))
            s := mload(add(signature, 0x40))
            v := byte(0, mload(add(signature, 0x60)))
        }

        return recover(hash, v, r, s);
    }

    /**
     * @dev Overload of {ECDSA-recover} that receives the `v`,
     * `r` and `s` signature fields separately.
     */
    function recover(bytes32 hash, uint8 v, bytes32 r, bytes32 s) internal pure returns (address) {
        // EIP-2 still allows signature malleability for ecrecover(). Remove this possibility and make the signature
        // unique. Appendix F in the Ethereum Yellow paper (https://ethereum.github.io/yellowpaper/paper.pdf), defines
        // the valid range for s in (281): 0 < s < secp256k1n ÷ 2 + 1, and for v in (282): v ∈ {27, 28}. Most
        // signatures from current libraries generate a unique signature with an s-value in the lower half order.
        //
        // If your library generates malleable signatures, such as s-values in the upper range, calculate a new s-value
        // with 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141 - s1 and flip v from 27 to 28 or
        // vice versa. If your library also generates signatures with 0/1 for v instead 27/28, add 27 to v to accept
        // these malleable signatures as well.
        require(uint256(s) <= 0x7FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF5D576E7357A4501DDFE92F46681B20A0, "ECDSA: invalid signature 's' value");
        require(v == 27 || v == 28, "ECDSA: invalid signature 'v' value");

        // If the signature is valid (and not malleable), return the signer address
        address signer = ecrecover(hash, v, r, s);
        require(signer != address(0), "ECDSA: invalid signature");

        return signer;
    }

    /**
     * @dev Returns an Ethereum Signed Message, created from a `hash`. This
     * produces hash corresponding to the one signed with the
     * https://eth.wiki/json-rpc/API#eth_sign[`eth_sign`]
     * JSON-RPC method as part of EIP-191.
     *
     * See {recover}.
     */
    function toEthSignedMessageHash(bytes32 hash) internal pure returns (bytes32) {
        // 32 is the length in bytes of hash,
        // enforced by the type signature above
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
    }

    /**
     * @dev Returns an Ethereum Signed Typed Data, created from a
     * `domainSeparator` and a `structHash`. This produces hash corresponding
     * to the one signed with the
     * https://eips.ethereum.org/EIPS/eip-712[`eth_signTypedData`]
     * JSON-RPC method as part of EIP-712.
     *
     * See {recover}.
     */
    function toTypedDataHash(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }
}


// File contracts/utils/cryptography/draft-EIP712.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev https://eips.ethereum.org/EIPS/eip-712[EIP 712] is a standard for hashing and signing of typed structured data.
 *
 * The encoding specified in the EIP is very generic, and such a generic implementation in Solidity is not feasible,
 * thus this contract does not implement the encoding itself. Protocols need to implement the type-specific encoding
 * they need in their contracts using a combination of `abi.encode` and `keccak256`.
 *
 * This contract implements the EIP 712 domain separator ({_domainSeparatorV4}) that is used as part of the encoding
 * scheme, and the final step of the encoding to obtain the message digest that is then signed via ECDSA
 * ({_hashTypedDataV4}).
 *
 * The implementation of the domain separator was designed to be as efficient as possible while still properly updating
 * the chain id to protect against replay attacks on an eventual fork of the chain.
 *
 * NOTE: This contract implements the version of the encoding known as "v4", as implemented by the JSON RPC method
 * https://docs.metamask.io/guide/signing-data.html[`eth_signTypedDataV4` in MetaMask].
 *
 * _Available since v3.4._
 */
abstract contract EIP712 {
    /* solhint-disable var-name-mixedcase */
    // Cache the domain separator as an immutable value, but also store the chain id that it corresponds to, in order to
    // invalidate the cached domain separator if the chain id changes.
    bytes32 private immutable _CACHED_DOMAIN_SEPARATOR;
    uint256 private immutable _CACHED_CHAIN_ID;

    bytes32 private immutable _HASHED_NAME;
    bytes32 private immutable _HASHED_VERSION;
    bytes32 private immutable _TYPE_HASH;
    /* solhint-enable var-name-mixedcase */

    /**
     * @dev Initializes the domain separator and parameter caches.
     *
     * The meaning of `name` and `version` is specified in
     * https://eips.ethereum.org/EIPS/eip-712#definition-of-domainseparator[EIP 712]:
     *
     * - `name`: the user readable name of the signing domain, i.e. the name of the DApp or the protocol.
     * - `version`: the current major version of the signing domain.
     *
     * NOTE: These parameters cannot be changed except through a xref:learn::upgrading-smart-contracts.adoc[smart
     * contract upgrade].
     */
    constructor(string memory name, string memory version) {
        bytes32 hashedName = keccak256(bytes(name));
        bytes32 hashedVersion = keccak256(bytes(version));
        bytes32 typeHash = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
        _HASHED_NAME = hashedName;
        _HASHED_VERSION = hashedVersion;
        _CACHED_CHAIN_ID = block.chainid;
        _CACHED_DOMAIN_SEPARATOR = _buildDomainSeparator(typeHash, hashedName, hashedVersion);
        _TYPE_HASH = typeHash;
    }

    /**
     * @dev Returns the domain separator for the current chain.
     */
    function _domainSeparatorV4() internal view returns (bytes32) {
        if (block.chainid == _CACHED_CHAIN_ID) {
            return _CACHED_DOMAIN_SEPARATOR;
        } else {
            return _buildDomainSeparator(_TYPE_HASH, _HASHED_NAME, _HASHED_VERSION);
        }
    }

    function _buildDomainSeparator(bytes32 typeHash, bytes32 name, bytes32 version) private view returns (bytes32) {
        return keccak256(
            abi.encode(
                typeHash,
                name,
                version,
                block.chainid,
                address(this)
            )
        );
    }

    /**
     * @dev Given an already https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct[hashed struct], this
     * function returns the hash of the fully encoded EIP712 message for this domain.
     *
     * This hash can be used together with {ECDSA-recover} to obtain the signer of a message. For example:
     *
     * ```solidity
     * bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
     *     keccak256("Mail(address to,string contents)"),
     *     mailTo,
     *     keccak256(bytes(mailContents))
     * )));
     * address signer = ECDSA.recover(digest, signature);
     * ```
     */
    function _hashTypedDataV4(bytes32 structHash) internal view virtual returns (bytes32) {
        return ECDSA.toTypedDataHash(_domainSeparatorV4(), structHash);
    }
}


// File contracts/metatx/MinimalForwarder.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/*
 * @dev Simple minimal forwarder to be used together with an ERC2771 compatible contract. See {ERC2771Context}.
 */
contract MinimalForwarder is EIP712 {
    using ECDSA for bytes32;

    struct ForwardRequest {
        address from;
        address to;
        uint256 value;
        uint256 gas;
        uint256 nonce;
        bytes data;
    }

    bytes32 private constant TYPEHASH = keccak256("ForwardRequest(address from,address to,uint256 value,uint256 gas,uint256 nonce,bytes data)");

    mapping(address => uint256) private _nonces;

    constructor() EIP712("MinimalForwarder", "0.0.1") {}

    function getNonce(address from) public view returns (uint256) {
        return _nonces[from];
    }

    function verify(ForwardRequest calldata req, bytes calldata signature) public view returns (bool) {
        address signer = _hashTypedDataV4(keccak256(abi.encode(
            TYPEHASH,
            req.from,
            req.to,
            req.value,
            req.gas,
            req.nonce,
            keccak256(req.data)
        ))).recover(signature);
        return _nonces[req.from] == req.nonce && signer == req.from;
    }

    function execute(ForwardRequest calldata req, bytes calldata signature) public payable returns (bool, bytes memory) {
        require(verify(req, signature), "MinimalForwarder: signature does not match request");
        _nonces[req.from] = req.nonce + 1;

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = req.to.call{gas: req.gas, value: req.value}(abi.encodePacked(req.data, req.from));
        // Validate that the relayer has sent enough gas for the call.
        // See https://ronan.eth.link/blog/ethereum-gas-dangers/
        assert(gasleft() > req.gas / 63);

        return (success, returndata);
    }
}


// File contracts/mocks/AccessControlEnumerableMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract AccessControlEnumerableMock is AccessControlEnumerable {
    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    function setRoleAdmin(bytes32 roleId, bytes32 adminRoleId) public {
        _setRoleAdmin(roleId, adminRoleId);
    }
}


// File contracts/mocks/AccessControlMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract AccessControlMock is AccessControl {
    constructor() {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
    }

    function setRoleAdmin(bytes32 roleId, bytes32 adminRoleId) public {
        _setRoleAdmin(roleId, adminRoleId);
    }
}


// File contracts/utils/Address.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Collection of functions related to the address type
 */
library Address {
    /**
     * @dev Returns true if `account` is a contract.
     *
     * [IMPORTANT]
     * ====
     * It is unsafe to assume that an address for which this function returns
     * false is an externally-owned account (EOA) and not a contract.
     *
     * Among others, `isContract` will return false for the following
     * types of addresses:
     *
     *  - an externally-owned account
     *  - a contract in construction
     *  - an address where a contract will be created
     *  - an address where a contract lived, but was destroyed
     * ====
     */
    function isContract(address account) internal view returns (bool) {
        // This method relies on extcodesize, which returns 0 for contracts in
        // construction, since the code is only stored at the end of the
        // constructor execution.

        uint256 size;
        // solhint-disable-next-line no-inline-assembly
        assembly { size := extcodesize(account) }
        return size > 0;
    }

    /**
     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
     * `recipient`, forwarding all available gas and reverting on errors.
     *
     * https://eips.ethereum.org/EIPS/eip-1884[EIP1884] increases the gas cost
     * of certain opcodes, possibly making contracts go over the 2300 gas limit
     * imposed by `transfer`, making them unable to receive funds via
     * `transfer`. {sendValue} removes this limitation.
     *
     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
     *
     * IMPORTANT: because control is transferred to `recipient`, care must be
     * taken to not create reentrancy vulnerabilities. Consider using
     * {ReentrancyGuard} or the
     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
     */
    function sendValue(address payable recipient, uint256 amount) internal {
        require(address(this).balance >= amount, "Address: insufficient balance");

        // solhint-disable-next-line avoid-low-level-calls, avoid-call-value
        (bool success, ) = recipient.call{ value: amount }("");
        require(success, "Address: unable to send value, recipient may have reverted");
    }

    /**
     * @dev Performs a Solidity function call using a low level `call`. A
     * plain`call` is an unsafe replacement for a function call: use this
     * function instead.
     *
     * If `target` reverts with a revert reason, it is bubbled up by this
     * function (like regular Solidity function calls).
     *
     * Returns the raw returned data. To convert to the expected return value,
     * use https://solidity.readthedocs.io/en/latest/units-and-global-variables.html?highlight=abi.decode#abi-encoding-and-decoding-functions[`abi.decode`].
     *
     * Requirements:
     *
     * - `target` must be a contract.
     * - calling `target` with `data` must not revert.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data) internal returns (bytes memory) {
      return functionCall(target, data, "Address: low-level call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`], but with
     * `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        return functionCallWithValue(target, data, 0, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but also transferring `value` wei to `target`.
     *
     * Requirements:
     *
     * - the calling contract must have an ETH balance of at least `value`.
     * - the called Solidity function must be `payable`.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value) internal returns (bytes memory) {
        return functionCallWithValue(target, data, value, "Address: low-level call with value failed");
    }

    /**
     * @dev Same as {xref-Address-functionCallWithValue-address-bytes-uint256-}[`functionCallWithValue`], but
     * with `errorMessage` as a fallback revert reason when `target` reverts.
     *
     * _Available since v3.1._
     */
    function functionCallWithValue(address target, bytes memory data, uint256 value, string memory errorMessage) internal returns (bytes memory) {
        require(address(this).balance >= value, "Address: insufficient balance for call");
        require(isContract(target), "Address: call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.call{ value: value }(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data) internal view returns (bytes memory) {
        return functionStaticCall(target, data, "Address: low-level static call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a static call.
     *
     * _Available since v3.3._
     */
    function functionStaticCall(address target, bytes memory data, string memory errorMessage) internal view returns (bytes memory) {
        require(isContract(target), "Address: static call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.staticcall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data) internal returns (bytes memory) {
        return functionDelegateCall(target, data, "Address: low-level delegate call failed");
    }

    /**
     * @dev Same as {xref-Address-functionCall-address-bytes-string-}[`functionCall`],
     * but performing a delegate call.
     *
     * _Available since v3.4._
     */
    function functionDelegateCall(address target, bytes memory data, string memory errorMessage) internal returns (bytes memory) {
        require(isContract(target), "Address: delegate call to non-contract");

        // solhint-disable-next-line avoid-low-level-calls
        (bool success, bytes memory returndata) = target.delegatecall(data);
        return _verifyCallResult(success, returndata, errorMessage);
    }

    function _verifyCallResult(bool success, bytes memory returndata, string memory errorMessage) private pure returns(bytes memory) {
        if (success) {
            return returndata;
        } else {
            // Look for revert reason and bubble it up if present
            if (returndata.length > 0) {
                // The easiest way to bubble the revert reason is using memory via assembly

                // solhint-disable-next-line no-inline-assembly
                assembly {
                    let returndata_size := mload(returndata)
                    revert(add(32, returndata), returndata_size)
                }
            } else {
                revert(errorMessage);
            }
        }
    }
}


// File contracts/mocks/AddressImpl.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract AddressImpl {
    string public sharedAnswer;

    event CallReturnValue(string data);

    function isContract(address account) external view returns (bool) {
        return Address.isContract(account);
    }

    function sendValue(address payable receiver, uint256 amount) external {
        Address.sendValue(receiver, amount);
    }

    function functionCall(address target, bytes calldata data) external {
        bytes memory returnData = Address.functionCall(target, data);
        emit CallReturnValue(abi.decode(returnData, (string)));
    }

    function functionCallWithValue(address target, bytes calldata data, uint256 value) external payable {
        bytes memory returnData = Address.functionCallWithValue(target, data, value);
        emit CallReturnValue(abi.decode(returnData, (string)));
    }

    function functionStaticCall(address target, bytes calldata data) external {
        bytes memory returnData = Address.functionStaticCall(target, data);
        emit CallReturnValue(abi.decode(returnData, (string)));
    }

    function functionDelegateCall(address target, bytes calldata data) external {
        bytes memory returnData = Address.functionDelegateCall(target, data);
        emit CallReturnValue(abi.decode(returnData, (string)));
    }

    // sendValue's tests require the contract to hold Ether
    receive () external payable { }
}


// File contracts/utils/math/Math.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Standard math utilities missing in the Solidity language.
 */
library Math {
    /**
     * @dev Returns the largest of two numbers.
     */
    function max(uint256 a, uint256 b) internal pure returns (uint256) {
        return a >= b ? a : b;
    }

    /**
     * @dev Returns the smallest of two numbers.
     */
    function min(uint256 a, uint256 b) internal pure returns (uint256) {
        return a < b ? a : b;
    }

    /**
     * @dev Returns the average of two numbers. The result is rounded towards
     * zero.
     */
    function average(uint256 a, uint256 b) internal pure returns (uint256) {
        // (a + b) / 2 can overflow, so we distribute
        return (a / 2) + (b / 2) + ((a % 2 + b % 2) / 2);
    }
}


// File contracts/utils/Arrays.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Collection of functions related to array types.
 */
library Arrays {
   /**
     * @dev Searches a sorted `array` and returns the first index that contains
     * a value greater or equal to `element`. If no such index exists (i.e. all
     * values in the array are strictly less than `element`), the array length is
     * returned. Time complexity O(log n).
     *
     * `array` is expected to be sorted in ascending order, and to contain no
     * repeated elements.
     */
    function findUpperBound(uint256[] storage array, uint256 element) internal view returns (uint256) {
        if (array.length == 0) {
            return 0;
        }

        uint256 low = 0;
        uint256 high = array.length;

        while (low < high) {
            uint256 mid = Math.average(low, high);

            // Note that mid will always be strictly less than high (i.e. it will be a valid array index)
            // because Math.average rounds down (it does integer division with truncation).
            if (array[mid] > element) {
                high = mid;
            } else {
                low = mid + 1;
            }
        }

        // At this point `low` is the exclusive upper bound. We will return the inclusive upper bound.
        if (low > 0 && array[low - 1] == element) {
            return low - 1;
        } else {
            return low;
        }
    }
}


// File contracts/mocks/ArraysImpl.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ArraysImpl {
    using Arrays for uint256[];

    uint256[] private _array;

    constructor (uint256[] memory array) {
        _array = array;
    }

    function findUpperBound(uint256 element) external view returns (uint256) {
        return _array.findUpperBound(element);
    }
}


// File contracts/proxy/Clones.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev https://eips.ethereum.org/EIPS/eip-1167[EIP 1167] is a standard for
 * deploying minimal proxy contracts, also known as "clones".
 *
 * > To simply and cheaply clone contract functionality in an immutable way, this standard specifies
 * > a minimal bytecode implementation that delegates all calls to a known, fixed address.
 *
 * The library includes functions to deploy a proxy using either `create` (traditional deployment) or `create2`
 * (salted deterministic deployment). It also includes functions to predict the addresses of clones deployed using the
 * deterministic method.
 *
 * _Available since v3.4._
 */
library Clones {
    /**
     * @dev Deploys and returns the address of a clone that mimics the behaviour of `implementation`.
     *
     * This function uses the create opcode, which should never revert.
     */
    function clone(address implementation) internal returns (address instance) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, implementation))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            instance := create(0, ptr, 0x37)
        }
        require(instance != address(0), "ERC1167: create failed");
    }

    /**
     * @dev Deploys and returns the address of a clone that mimics the behaviour of `implementation`.
     *
     * This function uses the create2 opcode and a `salt` to deterministically deploy
     * the clone. Using the same `implementation` and `salt` multiple time will revert, since
     * the clones cannot be deployed twice at the same address.
     */
    function cloneDeterministic(address implementation, bytes32 salt) internal returns (address instance) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, implementation))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            instance := create2(0, ptr, 0x37, salt)
        }
        require(instance != address(0), "ERC1167: create2 failed");
    }

    /**
     * @dev Computes the address of a clone deployed using {Clones-cloneDeterministic}.
     */
    function predictDeterministicAddress(address implementation, bytes32 salt, address deployer) internal pure returns (address predicted) {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            let ptr := mload(0x40)
            mstore(ptr, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(ptr, 0x14), shl(0x60, implementation))
            mstore(add(ptr, 0x28), 0x5af43d82803e903d91602b57fd5bf3ff00000000000000000000000000000000)
            mstore(add(ptr, 0x38), shl(0x60, deployer))
            mstore(add(ptr, 0x4c), salt)
            mstore(add(ptr, 0x6c), keccak256(ptr, 0x37))
            predicted := keccak256(add(ptr, 0x37), 0x55)
        }
    }

    /**
     * @dev Computes the address of a clone deployed using {Clones-cloneDeterministic}.
     */
    function predictDeterministicAddress(address implementation, bytes32 salt) internal view returns (address predicted) {
        return predictDeterministicAddress(implementation, salt, address(this));
    }
}


// File contracts/mocks/ClonesMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ClonesMock {
    using Address for address;
    using Clones for address;

    event NewInstance(address instance);

    function clone(address implementation, bytes calldata initdata) public payable {
        _initAndEmit(implementation.clone(), initdata);
    }

    function cloneDeterministic(address implementation, bytes32 salt, bytes calldata initdata) public payable {
        _initAndEmit(implementation.cloneDeterministic(salt), initdata);
    }

    function predictDeterministicAddress(address implementation, bytes32 salt) public view returns (address predicted) {
        return implementation.predictDeterministicAddress(salt);
    }

    function _initAndEmit(address instance, bytes memory initdata) private {
        if (initdata.length > 0) {
            instance.functionCallWithValue(initdata, msg.value);
        }
        emit NewInstance(instance);
    }
}


// File contracts/utils/escrow/Escrow.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
 /**
  * @title Escrow
  * @dev Base escrow contract, holds funds designated for a payee until they
  * withdraw them.
  *
  * Intended usage: This contract (and derived escrow contracts) should be a
  * standalone contract, that only interacts with the contract that instantiated
  * it. That way, it is guaranteed that all Ether will be handled according to
  * the `Escrow` rules, and there is no need to check for payable functions or
  * transfers in the inheritance tree. The contract that uses the escrow as its
  * payment method should be its owner, and provide public methods redirecting
  * to the escrow's deposit and withdraw.
  */
contract Escrow is Ownable {
    using Address for address payable;

    event Deposited(address indexed payee, uint256 weiAmount);
    event Withdrawn(address indexed payee, uint256 weiAmount);

    mapping(address => uint256) private _deposits;

    function depositsOf(address payee) public view returns (uint256) {
        return _deposits[payee];
    }

    /**
     * @dev Stores the sent amount as credit to be withdrawn.
     * @param payee The destination address of the funds.
     */
    function deposit(address payee) public payable virtual onlyOwner {
        uint256 amount = msg.value;
        _deposits[payee] = _deposits[payee] + amount;

        emit Deposited(payee, amount);
    }

    /**
     * @dev Withdraw accumulated balance for a payee, forwarding all gas to the
     * recipient.
     *
     * WARNING: Forwarding all gas opens the door to reentrancy vulnerabilities.
     * Make sure you trust the recipient, or are either following the
     * checks-effects-interactions pattern or using {ReentrancyGuard}.
     *
     * @param payee The address whose funds will be withdrawn and transferred to.
     */
    function withdraw(address payable payee) public virtual onlyOwner {
        uint256 payment = _deposits[payee];

        _deposits[payee] = 0;

        payee.sendValue(payment);

        emit Withdrawn(payee, payment);
    }
}


// File contracts/utils/escrow/ConditionalEscrow.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title ConditionalEscrow
 * @dev Base abstract escrow to only allow withdrawal if a condition is met.
 * @dev Intended usage: See {Escrow}. Same usage guidelines apply here.
 */
abstract contract ConditionalEscrow is Escrow {
    /**
     * @dev Returns whether an address is allowed to withdraw their funds. To be
     * implemented by derived contracts.
     * @param payee The destination address of the funds.
     */
    function withdrawalAllowed(address payee) public view virtual returns (bool);

    function withdraw(address payable payee) public virtual override {
        require(withdrawalAllowed(payee), "ConditionalEscrow: payee is not allowed to withdraw");
        super.withdraw(payee);
    }
}


// File contracts/mocks/ConditionalEscrowMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
// mock class using ConditionalEscrow
contract ConditionalEscrowMock is ConditionalEscrow {
    mapping(address => bool) private _allowed;

    function setAllowed(address payee, bool allowed) public {
        _allowed[payee] = allowed;
    }

    function withdrawalAllowed(address payee) public view override returns (bool) {
        return _allowed[payee];
    }
}


// File contracts/mocks/ContextMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ContextMock is Context {
    event Sender(address sender);

    function msgSender() public {
        emit Sender(_msgSender());
    }

    event Data(bytes data, uint256 integerValue, string stringValue);

    function msgData(uint256 integerValue, string memory stringValue) public {
        emit Data(_msgData(), integerValue, stringValue);
    }
}

contract ContextMockCaller {
    function callSender(ContextMock context) public {
        context.msgSender();
    }

    function callData(ContextMock context, uint256 integerValue, string memory stringValue) public {
        context.msgData(integerValue, stringValue);
    }
}


// File contracts/utils/Counters.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @title Counters
 * @author Matt Condon (@shrugs)
 * @dev Provides counters that can only be incremented or decremented by one. This can be used e.g. to track the number
 * of elements in a mapping, issuing ERC721 ids, or counting request ids.
 *
 * Include with `using Counters for Counters.Counter;`
 */
library Counters {
    struct Counter {
        // This variable should never be directly accessed by users of the library: interactions must be restricted to
        // the library's function. As of Solidity v0.5.2, this cannot be enforced, though there is a proposal to add
        // this feature: see https://github.com/ethereum/solidity/issues/4637
        uint256 _value; // default: 0
    }

    function current(Counter storage counter) internal view returns (uint256) {
        return counter._value;
    }

    function increment(Counter storage counter) internal {
        unchecked {
            counter._value += 1;
        }
    }

    function decrement(Counter storage counter) internal {
        uint256 value = counter._value;
        require(value > 0, "Counter: decrement overflow");
        unchecked {
            counter._value = value - 1;
        }
    }
}


// File contracts/mocks/CountersImpl.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract CountersImpl {
    using Counters for Counters.Counter;

    Counters.Counter private _counter;

    function current() public view returns (uint256) {
        return _counter.current();
    }

    function increment() public {
        _counter.increment();
    }

    function decrement() public {
        _counter.decrement();
    }
}


// File contracts/utils/Create2.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Helper to make usage of the `CREATE2` EVM opcode easier and safer.
 * `CREATE2` can be used to compute in advance the address where a smart
 * contract will be deployed, which allows for interesting new mechanisms known
 * as 'counterfactual interactions'.
 *
 * See the https://eips.ethereum.org/EIPS/eip-1014#motivation[EIP] for more
 * information.
 */
library Create2 {
    /**
     * @dev Deploys a contract using `CREATE2`. The address where the contract
     * will be deployed can be known in advance via {computeAddress}.
     *
     * The bytecode for a contract can be obtained from Solidity with
     * `type(contractName).creationCode`.
     *
     * Requirements:
     *
     * - `bytecode` must not be empty.
     * - `salt` must have not been used for `bytecode` already.
     * - the factory must have a balance of at least `amount`.
     * - if `amount` is non-zero, `bytecode` must have a `payable` constructor.
     */
    function deploy(uint256 amount, bytes32 salt, bytes memory bytecode) internal returns (address) {
        address addr;
        require(address(this).balance >= amount, "Create2: insufficient balance");
        require(bytecode.length != 0, "Create2: bytecode length is zero");
        // solhint-disable-next-line no-inline-assembly
        assembly {
            addr := create2(amount, add(bytecode, 0x20), mload(bytecode), salt)
        }
        require(addr != address(0), "Create2: Failed on deploy");
        return addr;
    }

    /**
     * @dev Returns the address where a contract will be stored if deployed via {deploy}. Any change in the
     * `bytecodeHash` or `salt` will result in a new destination address.
     */
    function computeAddress(bytes32 salt, bytes32 bytecodeHash) internal view returns (address) {
        return computeAddress(salt, bytecodeHash, address(this));
    }

    /**
     * @dev Returns the address where a contract will be stored if deployed via {deploy} from a contract located at
     * `deployer`. If `deployer` is this contract's address, returns the same value as {computeAddress}.
     */
    function computeAddress(bytes32 salt, bytes32 bytecodeHash, address deployer) internal pure returns (address) {
        bytes32 _data = keccak256(
            abi.encodePacked(bytes1(0xff), deployer, salt, bytecodeHash)
        );
        return address(uint160(uint256(_data)));
    }
}


// File contracts/utils/introspection/IERC1820Implementer.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Interface for an ERC1820 implementer, as defined in the
 * https://eips.ethereum.org/EIPS/eip-1820#interface-implementation-erc1820implementerinterface[EIP].
 * Used by contracts that will be registered as implementers in the
 * {IERC1820Registry}.
 */
interface IERC1820Implementer {
    /**
     * @dev Returns a special value (`ERC1820_ACCEPT_MAGIC`) if this contract
     * implements `interfaceHash` for `account`.
     *
     * See {IERC1820Registry-setInterfaceImplementer}.
     */
    function canImplementInterfaceForAddress(bytes32 interfaceHash, address account) external view returns (bytes32);
}


// File contracts/utils/introspection/ERC1820Implementer.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Implementation of the {IERC1820Implementer} interface.
 *
 * Contracts may inherit from this and call {_registerInterfaceForAddress} to
 * declare their willingness to be implementers.
 * {IERC1820Registry-setInterfaceImplementer} should then be called for the
 * registration to be complete.
 */
contract ERC1820Implementer is IERC1820Implementer {
    bytes32 private constant _ERC1820_ACCEPT_MAGIC = keccak256("ERC1820_ACCEPT_MAGIC");

    mapping(bytes32 => mapping(address => bool)) private _supportedInterfaces;

    /**
     * See {IERC1820Implementer-canImplementInterfaceForAddress}.
     */
    function canImplementInterfaceForAddress(bytes32 interfaceHash, address account) public view virtual override returns (bytes32) {
        return _supportedInterfaces[interfaceHash][account] ? _ERC1820_ACCEPT_MAGIC : bytes32(0x00);
    }

    /**
     * @dev Declares the contract as willing to be an implementer of
     * `interfaceHash` for `account`.
     *
     * See {IERC1820Registry-setInterfaceImplementer} and
     * {IERC1820Registry-interfaceHash}.
     */
    function _registerInterfaceForAddress(bytes32 interfaceHash, address account) internal virtual {
        _supportedInterfaces[interfaceHash][account] = true;
    }
}


// File contracts/mocks/Create2Impl.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Create2Impl {
    function deploy(uint256 value, bytes32 salt, bytes memory code) public {
        Create2.deploy(value, salt, code);
    }

    function deployERC1820Implementer(uint256 value, bytes32 salt) public {
        // solhint-disable-next-line indent
        Create2.deploy(value, salt, type(ERC1820Implementer).creationCode);
    }

    function computeAddress(bytes32 salt, bytes32 codeHash) public view returns (address) {
        return Create2.computeAddress(salt, codeHash);
    }

    function computeAddressWithDeployer(bytes32 salt, bytes32 codeHash, address deployer) public pure returns (address) {
        return Create2.computeAddress(salt, codeHash, deployer);
    }

    receive() external payable {}
}


// File contracts/mocks/ECDSAMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ECDSAMock {
    using ECDSA for bytes32;

    function recover(bytes32 hash, bytes memory signature) public pure returns (address) {
        return hash.recover(signature);
    }

    function toEthSignedMessageHash(bytes32 hash) public pure returns (bytes32) {
        return hash.toEthSignedMessageHash();
    }
}


// File contracts/mocks/EIP712External.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract EIP712External is EIP712 {
    constructor(string memory name, string memory version) EIP712(name, version) {}

    function domainSeparator() external view returns (bytes32) {
        return _domainSeparatorV4();
    }

    function verify(bytes memory signature, address signer, address mailTo, string memory mailContents) external view {
        bytes32 digest = _hashTypedDataV4(keccak256(abi.encode(
            keccak256("Mail(address to,string contents)"),
            mailTo,
            keccak256(bytes(mailContents))
        )));
        address recoveredSigner = ECDSA.recover(digest, signature);
        require(recoveredSigner == signer);
    }

    function getChainId() external view returns (uint256) {
        return block.chainid;
    }
}


// File contracts/utils/structs/EnumerableMap.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Library for managing an enumerable variant of Solidity's
 * https://solidity.readthedocs.io/en/latest/types.html#mapping-types[`mapping`]
 * type.
 *
 * Maps have the following properties:
 *
 * - Entries are added, removed, and checked for existence in constant time
 * (O(1)).
 * - Entries are enumerated in O(n). No guarantees are made on the ordering.
 *
 * ```
 * contract Example {
 *     // Add the library methods
 *     using EnumerableMap for EnumerableMap.UintToAddressMap;
 *
 *     // Declare a set state variable
 *     EnumerableMap.UintToAddressMap private myMap;
 * }
 * ```
 *
 * As of v3.0.0, only maps of type `uint256 -> address` (`UintToAddressMap`) are
 * supported.
 */
library EnumerableMap {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    // To implement this library for multiple types with as little code
    // repetition as possible, we write it in terms of a generic Map type with
    // bytes32 keys and values.
    // The Map implementation uses private functions, and user-facing
    // implementations (such as Uint256ToAddressMap) are just wrappers around
    // the underlying Map.
    // This means that we can only create new EnumerableMaps for types that fit
    // in bytes32.

    struct Map {
        // Storage of keys
        EnumerableSet.Bytes32Set _keys;

        mapping (bytes32 => bytes32) _values;
    }

    /**
     * @dev Adds a key-value pair to a map, or updates the value for an existing
     * key. O(1).
     *
     * Returns true if the key was added to the map, that is if it was not
     * already present.
     */
    function _set(Map storage map, bytes32 key, bytes32 value) private returns (bool) {
        map._values[key] = value;
        return map._keys.add(key);
    }

    /**
     * @dev Removes a key-value pair from a map. O(1).
     *
     * Returns true if the key was removed from the map, that is if it was present.
     */
    function _remove(Map storage map, bytes32 key) private returns (bool) {
        delete map._values[key];
        return map._keys.remove(key);
    }

    /**
     * @dev Returns true if the key is in the map. O(1).
     */
    function _contains(Map storage map, bytes32 key) private view returns (bool) {
        return map._keys.contains(key);
    }

    /**
     * @dev Returns the number of key-value pairs in the map. O(1).
     */
    function _length(Map storage map) private view returns (uint256) {
        return map._keys.length();
    }

   /**
    * @dev Returns the key-value pair stored at position `index` in the map. O(1).
    *
    * Note that there are no guarantees on the ordering of entries inside the
    * array, and it may change when more entries are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function _at(Map storage map, uint256 index) private view returns (bytes32, bytes32) {
        bytes32 key = map._keys.at(index);
        return (key, map._values[key]);
    }

    /**
     * @dev Tries to returns the value associated with `key`.  O(1).
     * Does not revert if `key` is not in the map.
     */
    function _tryGet(Map storage map, bytes32 key) private view returns (bool, bytes32) {
        bytes32 value = map._values[key];
        if (value == bytes32(0)) {
            return (_contains(map, key), bytes32(0));
        } else {
            return (true, value);
        }
    }

    /**
     * @dev Returns the value associated with `key`.  O(1).
     *
     * Requirements:
     *
     * - `key` must be in the map.
     */
    function _get(Map storage map, bytes32 key) private view returns (bytes32) {
        bytes32 value = map._values[key];
        require(value != 0 || _contains(map, key), "EnumerableMap: nonexistent key");
        return value;
    }

    /**
     * @dev Same as {_get}, with a custom error message when `key` is not in the map.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {_tryGet}.
     */
    function _get(Map storage map, bytes32 key, string memory errorMessage) private view returns (bytes32) {
        bytes32 value = map._values[key];
        require(value != 0 || _contains(map, key), errorMessage);
        return value;
    }

    // UintToAddressMap

    struct UintToAddressMap {
        Map _inner;
    }

    /**
     * @dev Adds a key-value pair to a map, or updates the value for an existing
     * key. O(1).
     *
     * Returns true if the key was added to the map, that is if it was not
     * already present.
     */
    function set(UintToAddressMap storage map, uint256 key, address value) internal returns (bool) {
        return _set(map._inner, bytes32(key), bytes32(uint256(uint160(value))));
    }

    /**
     * @dev Removes a value from a set. O(1).
     *
     * Returns true if the key was removed from the map, that is if it was present.
     */
    function remove(UintToAddressMap storage map, uint256 key) internal returns (bool) {
        return _remove(map._inner, bytes32(key));
    }

    /**
     * @dev Returns true if the key is in the map. O(1).
     */
    function contains(UintToAddressMap storage map, uint256 key) internal view returns (bool) {
        return _contains(map._inner, bytes32(key));
    }

    /**
     * @dev Returns the number of elements in the map. O(1).
     */
    function length(UintToAddressMap storage map) internal view returns (uint256) {
        return _length(map._inner);
    }

   /**
    * @dev Returns the element stored at position `index` in the set. O(1).
    * Note that there are no guarantees on the ordering of values inside the
    * array, and it may change when more values are added or removed.
    *
    * Requirements:
    *
    * - `index` must be strictly less than {length}.
    */
    function at(UintToAddressMap storage map, uint256 index) internal view returns (uint256, address) {
        (bytes32 key, bytes32 value) = _at(map._inner, index);
        return (uint256(key), address(uint160(uint256(value))));
    }

    /**
     * @dev Tries to returns the value associated with `key`.  O(1).
     * Does not revert if `key` is not in the map.
     *
     * _Available since v3.4._
     */
    function tryGet(UintToAddressMap storage map, uint256 key) internal view returns (bool, address) {
        (bool success, bytes32 value) = _tryGet(map._inner, bytes32(key));
        return (success, address(uint160(uint256(value))));
    }

    /**
     * @dev Returns the value associated with `key`.  O(1).
     *
     * Requirements:
     *
     * - `key` must be in the map.
     */
    function get(UintToAddressMap storage map, uint256 key) internal view returns (address) {
        return address(uint160(uint256(_get(map._inner, bytes32(key)))));
    }

    /**
     * @dev Same as {get}, with a custom error message when `key` is not in the map.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {tryGet}.
     */
    function get(UintToAddressMap storage map, uint256 key, string memory errorMessage) internal view returns (address) {
        return address(uint160(uint256(_get(map._inner, bytes32(key), errorMessage))));
    }
}


// File contracts/mocks/EnumerableMapMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract EnumerableMapMock {
    using EnumerableMap for EnumerableMap.UintToAddressMap;

    event OperationResult(bool result);

    EnumerableMap.UintToAddressMap private _map;

    function contains(uint256 key) public view returns (bool) {
        return _map.contains(key);
    }

    function set(uint256 key, address value) public {
        bool result = _map.set(key, value);
        emit OperationResult(result);
    }

    function remove(uint256 key) public {
        bool result = _map.remove(key);
        emit OperationResult(result);
    }

    function length() public view returns (uint256) {
        return _map.length();
    }

    function at(uint256 index) public view returns (uint256 key, address value) {
        return _map.at(index);
    }


    function tryGet(uint256 key) public view returns (bool, address) {
        return _map.tryGet(key);
    }

    function get(uint256 key) public view returns (address) {
        return _map.get(key);
    }

    function getWithMessage(uint256 key, string calldata errorMessage) public view returns (address) {
        return _map.get(key, errorMessage);
    }
}


// File contracts/mocks/EnumerableSetMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
// Bytes32Set
contract EnumerableBytes32SetMock {
    using EnumerableSet for EnumerableSet.Bytes32Set;

    event OperationResult(bool result);

    EnumerableSet.Bytes32Set private _set;

    function contains(bytes32 value) public view returns (bool) {
        return _set.contains(value);
    }

    function add(bytes32 value) public {
        bool result = _set.add(value);
        emit OperationResult(result);
    }

    function remove(bytes32 value) public {
        bool result = _set.remove(value);
        emit OperationResult(result);
    }

    function length() public view returns (uint256) {
        return _set.length();
    }

    function at(uint256 index) public view returns (bytes32) {
        return _set.at(index);
    }
}

// AddressSet
contract EnumerableAddressSetMock {
    using EnumerableSet for EnumerableSet.AddressSet;

    event OperationResult(bool result);

    EnumerableSet.AddressSet private _set;

    function contains(address value) public view returns (bool) {
        return _set.contains(value);
    }

    function add(address value) public {
        bool result = _set.add(value);
        emit OperationResult(result);
    }

    function remove(address value) public {
        bool result = _set.remove(value);
        emit OperationResult(result);
    }

    function length() public view returns (uint256) {
        return _set.length();
    }

    function at(uint256 index) public view returns (address) {
        return _set.at(index);
    }
}

// UintSet
contract EnumerableUintSetMock {
    using EnumerableSet for EnumerableSet.UintSet;

    event OperationResult(bool result);

    EnumerableSet.UintSet private _set;

    function contains(uint256 value) public view returns (bool) {
        return _set.contains(value);
    }

    function add(uint256 value) public {
        bool result = _set.add(value);
        emit OperationResult(result);
    }

    function remove(uint256 value) public {
        bool result = _set.remove(value);
        emit OperationResult(result);
    }

    function length() public view returns (uint256) {
        return _set.length();
    }

    function at(uint256 index) public view returns (uint256) {
        return _set.at(index);
    }
}


// File contracts/utils/Ownable.sol

// SPDX-License-Identifier: MIT
// OpenZeppelin Contracts v4.4.1 (access/Ownable.sol)

pragma solidity ^0.8.0;
/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor() {
        _transferOwnership(_msgSender());
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        _transferOwnership(address(0));
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        _transferOwnership(newOwner);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Internal function without access restriction.
     */
    function _transferOwnership(address newOwner) internal virtual {
        address oldOwner = _owner;
        _owner = newOwner;
        emit OwnershipTransferred(oldOwner, newOwner);
    }
}


// File contracts/token/ERC1155/IERC1155.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Required interface of an ERC1155 compliant contract, as defined in the
 * https://eips.ethereum.org/EIPS/eip-1155[EIP].
 *
 * _Available since v3.1._
 */
interface IERC1155 is IERC165 {
    /**
     * @dev Emitted when `value` tokens of token type `id` are transferred from `from` to `to` by `operator`.
     */
    event TransferSingle(address indexed operator, address indexed from, address indexed to, uint256 id, uint256 value);

    /**
     * @dev Equivalent to multiple {TransferSingle} events, where `operator`, `from` and `to` are the same for all
     * transfers.
     */
    event TransferBatch(address indexed operator, address indexed from, address indexed to, uint256[] ids, uint256[] values);

    /**
     * @dev Emitted when `account` grants or revokes permission to `operator` to transfer their tokens, according to
     * `approved`.
     */
    event ApprovalForAll(address indexed account, address indexed operator, bool approved);

    /**
     * @dev Emitted when the URI for token type `id` changes to `value`, if it is a non-programmatic URI.
     *
     * If an {URI} event was emitted for `id`, the standard
     * https://eips.ethereum.org/EIPS/eip-1155#metadata-extensions[guarantees] that `value` will equal the value
     * returned by {IERC1155MetadataURI-uri}.
     */
    event URI(string value, uint256 indexed id);

    /**
     * @dev Returns the amount of tokens of token type `id` owned by `account`.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     */
    function balanceOf(address account, uint256 id) external view returns (uint256);

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {balanceOf}.
     *
     * Requirements:
     *
     * - `accounts` and `ids` must have the same length.
     */
    function balanceOfBatch(address[] calldata accounts, uint256[] calldata ids) external view returns (uint256[] memory);

    /**
     * @dev Grants or revokes permission to `operator` to transfer the caller's tokens, according to `approved`,
     *
     * Emits an {ApprovalForAll} event.
     *
     * Requirements:
     *
     * - `operator` cannot be the caller.
     */
    function setApprovalForAll(address operator, bool approved) external;

    /**
     * @dev Returns true if `operator` is approved to transfer ``account``'s tokens.
     *
     * See {setApprovalForAll}.
     */
    function isApprovedForAll(address account, address operator) external view returns (bool);

    /**
     * @dev Transfers `amount` tokens of token type `id` from `from` to `to`.
     *
     * Emits a {TransferSingle} event.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - If the caller is not `from`, it must be have been approved to spend ``from``'s tokens via {setApprovalForAll}.
     * - `from` must have a balance of tokens of type `id` of at least `amount`.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the
     * acceptance magic value.
     */
    function safeTransferFrom(address from, address to, uint256 id, uint256 amount, bytes calldata data) external;

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {safeTransferFrom}.
     *
     * Emits a {TransferBatch} event.
     *
     * Requirements:
     *
     * - `ids` and `amounts` must have the same length.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155BatchReceived} and return the
     * acceptance magic value.
     */
    function safeBatchTransferFrom(address from, address to, uint256[] calldata ids, uint256[] calldata amounts, bytes calldata data) external;
}


// File contracts/token/ERC1155/IERC1155Receiver.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * _Available since v3.1._
 */
interface IERC1155Receiver is IERC165 {

    /**
        @dev Handles the receipt of a single ERC1155 token type. This function is
        called at the end of a `safeTransferFrom` after the balance has been updated.
        To accept the transfer, this must return
        `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))`
        (i.e. 0xf23a6e61, or its own function selector).
        @param operator The address which initiated the transfer (i.e. msg.sender)
        @param from The address which previously owned the token
        @param id The ID of the token being transferred
        @param value The amount of tokens being transferred
        @param data Additional data with no specified format
        @return `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))` if transfer is allowed
    */
    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    )
        external
        returns(bytes4);

    /**
        @dev Handles the receipt of a multiple ERC1155 token types. This function
        is called at the end of a `safeBatchTransferFrom` after the balances have
        been updated. To accept the transfer(s), this must return
        `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))`
        (i.e. 0xbc197c81, or its own function selector).
        @param operator The address which initiated the batch transfer (i.e. msg.sender)
        @param from The address which previously owned the token
        @param ids An array containing ids of each token being transferred (order and length must match values array)
        @param values An array containing amounts of each token being transferred (order and length must match ids array)
        @param data Additional data with no specified format
        @return `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))` if transfer is allowed
    */
    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    )
        external
        returns(bytes4);
}


// File contracts/token/ERC1155/extensions/IERC1155MetadataURI.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Interface of the optional ERC1155MetadataExtension interface, as defined
 * in the https://eips.ethereum.org/EIPS/eip-1155#metadata-extensions[EIP].
 *
 * _Available since v3.1._
 */
interface IERC1155MetadataURI is IERC1155 {
    /**
     * @dev Returns the URI for token type `id`.
     *
     * If the `\{id\}` substring is present in the URI, it must be replaced by
     * clients with the actual token type ID.
     */
    function uri(uint256 id) external view returns (string memory);
}


// File contracts/token/ERC1155/ERC1155.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 *
 * @dev Implementation of the basic standard multi-token.
 * See https://eips.ethereum.org/EIPS/eip-1155
 * Originally based on code by Enjin: https://github.com/enjin/erc-1155
 *
 * _Available since v3.1._
 */
contract ERC1155 is Ownable, ERC165, IERC1155, IERC1155MetadataURI {
    using Address for address;

    // Mapping from token ID to account balances
    mapping (uint256 => mapping(address => uint256)) private _balances;

    // Mapping from account to operator approvals
    mapping (address => mapping(address => bool)) private _operatorApprovals;

    // Used as the URI for all token types by relying on ID substitution, e.g. https://token-cdn-domain/{id}.json
    string private _uri;

    /**
     * @dev See {_setURI}.
     */
    constructor (string memory uri_) {
        _setURI(uri_);
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IERC1155).interfaceId
            || interfaceId == type(IERC1155MetadataURI).interfaceId
            || super.supportsInterface(interfaceId);
    }

    /**
     * @dev See {IERC1155MetadataURI-uri}.
     *
     * This implementation returns the same URI for *all* token types. It relies
     * on the token type ID substitution mechanism
     * https://eips.ethereum.org/EIPS/eip-1155#metadata[defined in the EIP].
     *
     * Clients calling this function must replace the `\{id\}` substring with the
     * actual token type ID.
     */
    function uri(uint256) external view virtual override returns (string memory) {
        return _uri;
    }

    /**
     * @dev See {IERC1155-balanceOf}.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     */
    function balanceOf(address account, uint256 id) public view virtual override returns (uint256) {
        require(account != address(0), "ERC1155: balance query for the zero address");
        return _balances[id][account];
    }

    /**
     * @dev See {IERC1155-balanceOfBatch}.
     *
     * Requirements:
     *
     * - `accounts` and `ids` must have the same length.
     */
    function balanceOfBatch(
        address[] memory accounts,
        uint256[] memory ids
    )
        public
        view
        virtual
        override
        returns (uint256[] memory)
    {
        require(accounts.length == ids.length, "ERC1155: accounts and ids length mismatch");

        uint256[] memory batchBalances = new uint256[](accounts.length);

        for (uint256 i = 0; i < accounts.length; ++i) {
            batchBalances[i] = balanceOf(accounts[i], ids[i]);
        }

        return batchBalances;
    }

    /**
     * @dev See {IERC1155-setApprovalForAll}.
     */
    function setApprovalForAll(address operator, bool approved) public virtual override {
        require(_msgSender() != operator, "ERC1155: setting approval status for self");

        _operatorApprovals[_msgSender()][operator] = approved;
        emit ApprovalForAll(_msgSender(), operator, approved);
    }

    /**
     * @dev See {IERC1155-isApprovedForAll}.
     */
    function isApprovedForAll(address account, address operator) public view virtual override returns (bool) {
        return _operatorApprovals[account][operator];
    }

    /**
     * @dev See {IERC1155-safeTransferFrom}.
     */
    function safeTransferFrom(
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    )
        public
        virtual
        override
    {
        require(to != address(0), "ERC1155: transfer to the zero address");
        require(
            from == _msgSender() || isApprovedForAll(from, _msgSender()),
            "ERC1155: caller is not owner nor approved"
        );

        address operator = _msgSender();

        _beforeTokenTransfer(operator, from, to, _asSingletonArray(id), _asSingletonArray(amount), data);

        uint256 fromBalance = _balances[id][from];
        require(fromBalance >= amount, "ERC1155: insufficient balance for transfer");
        _balances[id][from] = fromBalance - amount;
        _balances[id][to] += amount;

        emit TransferSingle(operator, from, to, id, amount);

        _doSafeTransferAcceptanceCheck(operator, from, to, id, amount, data);
    }

    /**
     * @dev See {IERC1155-safeBatchTransferFrom}.
     */
    function safeBatchTransferFrom(
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
        public
        virtual
        override
    {
        require(ids.length == amounts.length, "ERC1155: ids and amounts length mismatch");
        require(to != address(0), "ERC1155: transfer to the zero address");
        require(
            from == _msgSender() || isApprovedForAll(from, _msgSender()),
            "ERC1155: transfer caller is not owner nor approved"
        );

        address operator = _msgSender();

        _beforeTokenTransfer(operator, from, to, ids, amounts, data);

        for (uint256 i = 0; i < ids.length; ++i) {
            uint256 id = ids[i];
            uint256 amount = amounts[i];

            uint256 fromBalance = _balances[id][from];
            require(fromBalance >= amount, "ERC1155: insufficient balance for transfer");
            _balances[id][from] = fromBalance - amount;
            _balances[id][to] += amount;
        }

        emit TransferBatch(operator, from, to, ids, amounts);

        _doSafeBatchTransferAcceptanceCheck(operator, from, to, ids, amounts, data);
    }

    /**
     * @dev Sets a new URI for all token types, by relying on the token type ID
     * substitution mechanism
     * https://eips.ethereum.org/EIPS/eip-1155#metadata[defined in the EIP].
     *
     * By this mechanism, any occurrence of the `\{id\}` substring in either the
     * URI or any of the amounts in the JSON file at said URI will be replaced by
     * clients with the token type ID.
     *
     * For example, the `https://token-cdn-domain/\{id\}.json` URI would be
     * interpreted by clients as
     * `https://token-cdn-domain/000000000000000000000000000000000000000000000000000000000004cce0.json`
     * for token type ID 0x4cce0.
     *
     * See {uri}.
     *
     * Because these URIs cannot be meaningfully represented by the {URI} event,
     * this function emits no events.
     */
    function _setURI(string memory newuri) internal virtual {
        _uri = newuri;
    }

    /**
     * @dev Creates `amount` tokens of token type `id`, and assigns them to `account`.
     *
     * Emits a {TransferSingle} event.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     * - If `account` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155Received} and return the
     * acceptance magic value.
     */
    function _mint(address account, uint256 id, uint256 amount, bytes memory data) internal virtual {
        require(account != address(0), "ERC1155: mint to the zero address");

        address operator = _msgSender();

        _beforeTokenTransfer(operator, address(0), account, _asSingletonArray(id), _asSingletonArray(amount), data);

        _balances[id][account] += amount;
        emit TransferSingle(operator, address(0), account, id, amount);

        _doSafeTransferAcceptanceCheck(operator, address(0), account, id, amount, data);
    }

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {_mint}.
     *
     * Requirements:
     *
     * - `ids` and `amounts` must have the same length.
     * - If `to` refers to a smart contract, it must implement {IERC1155Receiver-onERC1155BatchReceived} and return the
     * acceptance magic value.
     */
    function _mintBatch(address to, uint256[] memory ids, uint256[] memory amounts, bytes memory data) internal virtual {
        require(to != address(0), "ERC1155: mint to the zero address");
        require(ids.length == amounts.length, "ERC1155: ids and amounts length mismatch");

        address operator = _msgSender();

        _beforeTokenTransfer(operator, address(0), to, ids, amounts, data);

        for (uint i = 0; i < ids.length; i++) {
            _balances[ids[i]][to] += amounts[i];
        }

        emit TransferBatch(operator, address(0), to, ids, amounts);

        _doSafeBatchTransferAcceptanceCheck(operator, address(0), to, ids, amounts, data);
    }

    /**
     * @dev Destroys `amount` tokens of token type `id` from `account`
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     * - `account` must have at least `amount` tokens of token type `id`.
     */
    function _burn(address account, uint256 id, uint256 amount) internal virtual {
        require(account != address(0), "ERC1155: burn from the zero address");

        address operator = _msgSender();

        _beforeTokenTransfer(operator, account, address(0), _asSingletonArray(id), _asSingletonArray(amount), "");

        uint256 accountBalance = _balances[id][account];
        require(accountBalance >= amount, "ERC1155: burn amount exceeds balance");
        _balances[id][account] = accountBalance - amount;

        emit TransferSingle(operator, account, address(0), id, amount);
    }

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] version of {_burn}.
     *
     * Requirements:
     *
     * - `ids` and `amounts` must have the same length.
     */
    function _burnBatch(address account, uint256[] memory ids, uint256[] memory amounts) internal virtual {
        require(account != address(0), "ERC1155: burn from the zero address");
        require(ids.length == amounts.length, "ERC1155: ids and amounts length mismatch");

        address operator = _msgSender();

        _beforeTokenTransfer(operator, account, address(0), ids, amounts, "");

        for (uint i = 0; i < ids.length; i++) {
            uint256 id = ids[i];
            uint256 amount = amounts[i];

            uint256 accountBalance = _balances[id][account];
            require(accountBalance >= amount, "ERC1155: burn amount exceeds balance");
            _balances[id][account] = accountBalance - amount;
        }

        emit TransferBatch(operator, account, address(0), ids, amounts);
    }

    /**
     * @dev Hook that is called before any token transfer. This includes minting
     * and burning, as well as batched variants.
     *
     * The same hook is called on both single and batched variants. For single
     * transfers, the length of the `id` and `amount` arrays will be 1.
     *
     * Calling conditions (for each `id` and `amount` pair):
     *
     * - When `from` and `to` are both non-zero, `amount` of ``from``'s tokens
     * of token type `id` will be  transferred to `to`.
     * - When `from` is zero, `amount` tokens of token type `id` will be minted
     * for `to`.
     * - when `to` is zero, `amount` of ``from``'s tokens of token type `id`
     * will be burned.
     * - `from` and `to` are never both zero.
     * - `ids` and `amounts` have the same, non-zero length.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
        internal
        virtual
    { }

    function _doSafeTransferAcceptanceCheck(
        address operator,
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    )
        private
    {
        if (to.isContract()) {
            try IERC1155Receiver(to).onERC1155Received(operator, from, id, amount, data) returns (bytes4 response) {
                if (response != IERC1155Receiver(to).onERC1155Received.selector) {
                    revert("ERC1155: ERC1155Receiver rejected tokens");
                }
            } catch Error(string memory reason) {
                revert(reason);
            } catch {
                revert("ERC1155: transfer to non ERC1155Receiver implementer");
            }
        }
    }

    function _doSafeBatchTransferAcceptanceCheck(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
        private
    {
        if (to.isContract()) {
            try IERC1155Receiver(to).onERC1155BatchReceived(operator, from, ids, amounts, data) returns (bytes4 response) {
                if (response != IERC1155Receiver(to).onERC1155BatchReceived.selector) {
                    revert("ERC1155: ERC1155Receiver rejected tokens");
                }
            } catch Error(string memory reason) {
                revert(reason);
            } catch {
                revert("ERC1155: transfer to non ERC1155Receiver implementer");
            }
        }
    }

    function _asSingletonArray(uint256 element) private pure returns (uint256[] memory) {
        uint256[] memory array = new uint256[](1);
        array[0] = element;

        return array;
    }
}


// File contracts/token/ERC1155/extensions/ERC1155Burnable.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Extension of {ERC1155} that allows token holders to destroy both their
 * own tokens and those that they have been approved to use.
 *
 * _Available since v3.1._
 */
abstract contract ERC1155Burnable is ERC1155 {
    function burn(address account, uint256 id, uint256 value) public virtual {
        require(
            account == _msgSender() || isApprovedForAll(account, _msgSender()),
            "ERC1155: caller is not owner nor approved"
        );

        _burn(account, id, value);
    }

    function burnBatch(address account, uint256[] memory ids, uint256[] memory values) public virtual {
        require(
            account == _msgSender() || isApprovedForAll(account, _msgSender()),
            "ERC1155: caller is not owner nor approved"
        );

        _burnBatch(account, ids, values);
    }
}


// File contracts/mocks/ERC1155BurnableMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC1155BurnableMock is ERC1155Burnable {
    constructor(string memory uri) ERC1155(uri) { }

    function mint(address to, uint256 id, uint256 value, bytes memory data) public {
        _mint(to, id, value, data);
    }
}


// File contracts/mocks/ERC1155Mock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title ERC1155Mock
 * This mock just publicizes internal functions for testing purposes
 */
contract ERC1155Mock is ERC1155 {
    constructor (string memory uri) ERC1155(uri) {
        // solhint-disable-previous-line no-empty-blocks
    }

    function setURI(string memory newuri) public {
        _setURI(newuri);
    }

    function mint(address to, uint256 id, uint256 value, bytes memory data) public {
        _mint(to, id, value, data);
    }

    function mintBatch(address to, uint256[] memory ids, uint256[] memory values, bytes memory data) public {
        _mintBatch(to, ids, values, data);
    }

    function burn(address owner, uint256 id, uint256 value) public {
        _burn(owner, id, value);
    }

    function burnBatch(address owner, uint256[] memory ids, uint256[] memory values) public {
        _burnBatch(owner, ids, values);
    }
}


// File contracts/security/Pausable.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Contract module which allows children to implement an emergency stop
 * mechanism that can be triggered by an authorized account.
 *
 * This module is used through inheritance. It will make available the
 * modifiers `whenNotPaused` and `whenPaused`, which can be applied to
 * the functions of your contract. Note that they will not be pausable by
 * simply including this module, only once the modifiers are put in place.
 */
abstract contract Pausable is Context {
    /**
     * @dev Emitted when the pause is triggered by `account`.
     */
    event Paused(address account);

    /**
     * @dev Emitted when the pause is lifted by `account`.
     */
    event Unpaused(address account);

    bool private _paused;

    /**
     * @dev Initializes the contract in unpaused state.
     */
    constructor () {
        _paused = false;
    }

    /**
     * @dev Returns true if the contract is paused, and false otherwise.
     */
    function paused() public view virtual returns (bool) {
        return _paused;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is not paused.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    modifier whenNotPaused() {
        require(!paused(), "Pausable: paused");
        _;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is paused.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    modifier whenPaused() {
        require(paused(), "Pausable: not paused");
        _;
    }

    /**
     * @dev Triggers stopped state.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    function _pause() internal virtual whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }

    /**
     * @dev Returns to normal state.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    function _unpause() internal virtual whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }
}


// File contracts/token/ERC1155/extensions/ERC1155Pausable.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev ERC1155 token with pausable token transfers, minting and burning.
 *
 * Useful for scenarios such as preventing trades until the end of an evaluation
 * period, or having an emergency switch for freezing all token transfers in the
 * event of a large bug.
 *
 * _Available since v3.1._
 */
abstract contract ERC1155Pausable is ERC1155, Pausable {
    /**
     * @dev See {ERC1155-_beforeTokenTransfer}.
     *
     * Requirements:
     *
     * - the contract must not be paused.
     */
    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
        internal
        virtual
        override
    {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);

        require(!paused(), "ERC1155Pausable: token transfer while paused");
    }
}


// File contracts/mocks/ERC1155PausableMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC1155PausableMock is ERC1155Mock, ERC1155Pausable {
    constructor(string memory uri) ERC1155Mock(uri) { }

    function pause() external {
        _pause();
    }

    function unpause() external {
        _unpause();
    }

    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
        internal virtual override(ERC1155, ERC1155Pausable)
    {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
    }
}


// File contracts/mocks/ERC1155ReceiverMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC1155ReceiverMock is IERC1155Receiver, ERC165 {
    bytes4 private _recRetval;
    bool private _recReverts;
    bytes4 private _batRetval;
    bool private _batReverts;

    event Received(address operator, address from, uint256 id, uint256 value, bytes data, uint256 gas);
    event BatchReceived(address operator, address from, uint256[] ids, uint256[] values, bytes data, uint256 gas);

    constructor (
        bytes4 recRetval,
        bool recReverts,
        bytes4 batRetval,
        bool batReverts
    )
    {
        _recRetval = recRetval;
        _recReverts = recReverts;
        _batRetval = batRetval;
        _batReverts = batReverts;
    }

    function onERC1155Received(
        address operator,
        address from,
        uint256 id,
        uint256 value,
        bytes calldata data
    )
        external
        override
        returns(bytes4)
    {
        require(!_recReverts, "ERC1155ReceiverMock: reverting on receive");
        emit Received(operator, from, id, value, data, gasleft());
        return _recRetval;
    }

    function onERC1155BatchReceived(
        address operator,
        address from,
        uint256[] calldata ids,
        uint256[] calldata values,
        bytes calldata data
    )
        external
        override
        returns(bytes4)
    {
        require(!_batReverts, "ERC1155ReceiverMock: reverting on batch receive");
        emit BatchReceived(operator, from, ids, values, data, gasleft());
        return _batRetval;
    }
}


// File contracts/mocks/ERC165/ERC165InterfacesSupported.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * https://eips.ethereum.org/EIPS/eip-214#specification
 * From the specification:
 * > Any attempts to make state-changing operations inside an execution instance with STATIC set to true will instead
 * throw an exception.
 * > These operations include [...], LOG0, LOG1, LOG2, [...]
 *
 * therefore, because this contract is staticcall'd we need to not emit events (which is how solidity-coverage works)
 * solidity-coverage ignores the /mocks folder, so we duplicate its implementation here to avoid instrumenting it
 */
contract SupportsInterfaceWithLookupMock is IERC165 {
    /*
     * bytes4(keccak256('supportsInterface(bytes4)')) == 0x01ffc9a7
     */
    bytes4 public constant INTERFACE_ID_ERC165 = 0x01ffc9a7;

    /**
     * @dev A mapping of interface id to whether or not it's supported.
     */
    mapping(bytes4 => bool) private _supportedInterfaces;

    /**
     * @dev A contract implementing SupportsInterfaceWithLookup
     * implement ERC165 itself.
     */
    constructor () {
        _registerInterface(INTERFACE_ID_ERC165);
    }

    /**
     * @dev Implement supportsInterface(bytes4) using a lookup table.
     */
    function supportsInterface(bytes4 interfaceId) public view override returns (bool) {
        return _supportedInterfaces[interfaceId];
    }

    /**
     * @dev Private method for registering an interface.
     */
    function _registerInterface(bytes4 interfaceId) internal {
        require(interfaceId != 0xffffffff, "ERC165InterfacesSupported: invalid interface id");
        _supportedInterfaces[interfaceId] = true;
    }
}

contract ERC165InterfacesSupported is SupportsInterfaceWithLookupMock {
    constructor (bytes4[] memory interfaceIds) {
        for (uint256 i = 0; i < interfaceIds.length; i++) {
            _registerInterface(interfaceIds[i]);
        }
    }
}


// File contracts/utils/introspection/ERC165Checker.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Library used to query support of an interface declared via {IERC165}.
 *
 * Note that these functions return the actual result of the query: they do not
 * `revert` if an interface is not supported. It is up to the caller to decide
 * what to do in these cases.
 */
library ERC165Checker {
    // As per the EIP-165 spec, no interface should ever match 0xffffffff
    bytes4 private constant _INTERFACE_ID_INVALID = 0xffffffff;

    /**
     * @dev Returns true if `account` supports the {IERC165} interface,
     */
    function supportsERC165(address account) internal view returns (bool) {
        // Any contract that implements ERC165 must explicitly indicate support of
        // InterfaceId_ERC165 and explicitly indicate non-support of InterfaceId_Invalid
        return _supportsERC165Interface(account, type(IERC165).interfaceId) &&
            !_supportsERC165Interface(account, _INTERFACE_ID_INVALID);
    }

    /**
     * @dev Returns true if `account` supports the interface defined by
     * `interfaceId`. Support for {IERC165} itself is queried automatically.
     *
     * See {IERC165-supportsInterface}.
     */
    function supportsInterface(address account, bytes4 interfaceId) internal view returns (bool) {
        // query support of both ERC165 as per the spec and support of _interfaceId
        return supportsERC165(account) &&
            _supportsERC165Interface(account, interfaceId);
    }

    /**
     * @dev Returns a boolean array where each value corresponds to the
     * interfaces passed in and whether they're supported or not. This allows
     * you to batch check interfaces for a contract where your expectation
     * is that some interfaces may not be supported.
     *
     * See {IERC165-supportsInterface}.
     *
     * _Available since v3.4._
     */
    function getSupportedInterfaces(address account, bytes4[] memory interfaceIds) internal view returns (bool[] memory) {
        // an array of booleans corresponding to interfaceIds and whether they're supported or not
        bool[] memory interfaceIdsSupported = new bool[](interfaceIds.length);

        // query support of ERC165 itself
        if (supportsERC165(account)) {
            // query support of each interface in interfaceIds
            for (uint256 i = 0; i < interfaceIds.length; i++) {
                interfaceIdsSupported[i] = _supportsERC165Interface(account, interfaceIds[i]);
            }
        }

        return interfaceIdsSupported;
    }

    /**
     * @dev Returns true if `account` supports all the interfaces defined in
     * `interfaceIds`. Support for {IERC165} itself is queried automatically.
     *
     * Batch-querying can lead to gas savings by skipping repeated checks for
     * {IERC165} support.
     *
     * See {IERC165-supportsInterface}.
     */
    function supportsAllInterfaces(address account, bytes4[] memory interfaceIds) internal view returns (bool) {
        // query support of ERC165 itself
        if (!supportsERC165(account)) {
            return false;
        }

        // query support of each interface in _interfaceIds
        for (uint256 i = 0; i < interfaceIds.length; i++) {
            if (!_supportsERC165Interface(account, interfaceIds[i])) {
                return false;
            }
        }

        // all interfaces supported
        return true;
    }

    /**
     * @notice Query if a contract implements an interface, does not check ERC165 support
     * @param account The address of the contract to query for support of an interface
     * @param interfaceId The interface identifier, as specified in ERC-165
     * @return true if the contract at account indicates support of the interface with
     * identifier interfaceId, false otherwise
     * @dev Assumes that account contains a contract that supports ERC165, otherwise
     * the behavior of this method is undefined. This precondition can be checked
     * with {supportsERC165}.
     * Interface identification is specified in ERC-165.
     */
    function _supportsERC165Interface(address account, bytes4 interfaceId) private view returns (bool) {
        bytes memory encodedParams = abi.encodeWithSelector(IERC165(account).supportsInterface.selector, interfaceId);
        (bool success, bytes memory result) = account.staticcall{ gas: 30000 }(encodedParams);
        if (result.length < 32) return false;
        return success && abi.decode(result, (bool));
    }
}


// File contracts/mocks/ERC165CheckerMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC165CheckerMock {
    using ERC165Checker for address;

    function supportsERC165(address account) public view returns (bool) {
        return account.supportsERC165();
    }

    function supportsInterface(address account, bytes4 interfaceId) public view returns (bool) {
        return account.supportsInterface(interfaceId);
    }

    function supportsAllInterfaces(address account, bytes4[] memory interfaceIds) public view returns (bool) {
        return account.supportsAllInterfaces(interfaceIds);
    }

    function getSupportedInterfaces(address account, bytes4[] memory interfaceIds) public view returns (bool[] memory) {
        return account.getSupportedInterfaces(interfaceIds);
    }
}


// File contracts/mocks/ERC165Mock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC165Mock is ERC165 {
}


// File contracts/utils/introspection/ERC165Storage.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Storage based implementation of the {IERC165} interface.
 *
 * Contracts may inherit from this and call {_registerInterface} to declare
 * their support of an interface.
 */
abstract contract ERC165Storage is ERC165 {
    /**
     * @dev Mapping of interface ids to whether or not it's supported.
     */
    mapping(bytes4 => bool) private _supportedInterfaces;

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        return super.supportsInterface(interfaceId) || _supportedInterfaces[interfaceId];
    }

    /**
     * @dev Registers the contract as an implementer of the interface defined by
     * `interfaceId`. Support of the actual ERC165 interface is automatic and
     * registering its interface id is not required.
     *
     * See {IERC165-supportsInterface}.
     *
     * Requirements:
     *
     * - `interfaceId` cannot be the ERC165 invalid interface (`0xffffffff`).
     */
    function _registerInterface(bytes4 interfaceId) internal virtual {
        require(interfaceId != 0xffffffff, "ERC165: invalid interface id");
        _supportedInterfaces[interfaceId] = true;
    }
}


// File contracts/mocks/ERC165StorageMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC165StorageMock is ERC165Storage {
    function registerInterface(bytes4 interfaceId) public {
        _registerInterface(interfaceId);
    }
}


// File contracts/mocks/ERC1820ImplementerMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC1820ImplementerMock is ERC1820Implementer {
    function registerInterfaceForAddress(bytes32 interfaceHash, address account) public {
        _registerInterfaceForAddress(interfaceHash, account);
    }
}


// File contracts/token/ERC20/IERC20.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}


// File contracts/token/ERC20/ERC20.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Implementation of the {IERC20} interface.
 *
 * This implementation is agnostic to the way tokens are created. This means
 * that a supply mechanism has to be added in a derived contract using {_mint}.
 * For a generic mechanism see {ERC20PresetMinterPauser}.
 *
 * TIP: For a detailed writeup see our guide
 * https://forum.zeppelin.solutions/t/how-to-implement-erc20-supply-mechanisms/226[How
 * to implement supply mechanisms].
 *
 * We have followed general OpenZeppelin guidelines: functions revert instead
 * of returning `false` on failure. This behavior is nonetheless conventional
 * and does not conflict with the expectations of ERC20 applications.
 *
 * Additionally, an {Approval} event is emitted on calls to {transferFrom}.
 * This allows applications to reconstruct the allowance for all accounts just
 * by listening to said events. Other implementations of the EIP may not emit
 * these events, as it isn't required by the specification.
 *
 * Finally, the non-standard {decreaseAllowance} and {increaseAllowance}
 * functions have been added to mitigate the well-known issues around setting
 * allowances. See {IERC20-approve}.
 */
contract ERC20 is Context, IERC20 {
    mapping (address => uint256) private _balances;

    mapping (address => mapping (address => uint256)) private _allowances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;

    /**
     * @dev Sets the values for {name} and {symbol}.
     *
     * The defaut value of {decimals} is 18. To select a different value for
     * {decimals} you should overload it.
     *
     * All three of these values are immutable: they can only be set once during
     * construction.
     */
    constructor (string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    /**
     * @dev Returns the name of the token.
     */
    function name() public view virtual returns (string memory) {
        return _name;
    }

    /**
     * @dev Returns the symbol of the token, usually a shorter version of the
     * name.
     */
    function symbol() public view virtual returns (string memory) {
        return _symbol;
    }

    /**
     * @dev Returns the number of decimals used to get its user representation.
     * For example, if `decimals` equals `2`, a balance of `505` tokens should
     * be displayed to a user as `5,05` (`505 / 10 ** 2`).
     *
     * Tokens usually opt for a value of 18, imitating the relationship between
     * Ether and Wei. This is the value {ERC20} uses, unless this function is
     * overloaded;
     *
     * NOTE: This information is only used for _display_ purposes: it in
     * no way affects any of the arithmetic of the contract, including
     * {IERC20-balanceOf} and {IERC20-transfer}.
     */
    function decimals() public view virtual returns (uint8) {
        return 18;
    }

    /**
     * @dev See {IERC20-totalSupply}.
     */
    function totalSupply() public view virtual override returns (uint256) {
        return _totalSupply;
    }

    /**
     * @dev See {IERC20-balanceOf}.
     */
    function balanceOf(address account) public view virtual override returns (uint256) {
        return _balances[account];
    }

    /**
     * @dev See {IERC20-transfer}.
     *
     * Requirements:
     *
     * - `recipient` cannot be the zero address.
     * - the caller must have a balance of at least `amount`.
     */
    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    /**
     * @dev See {IERC20-allowance}.
     */
    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }

    /**
     * @dev See {IERC20-approve}.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    /**
     * @dev See {IERC20-transferFrom}.
     *
     * Emits an {Approval} event indicating the updated allowance. This is not
     * required by the EIP. See the note at the beginning of {ERC20}.
     *
     * Requirements:
     *
     * - `sender` and `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     * - the caller must have allowance for ``sender``'s tokens of at least
     * `amount`.
     */
    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(sender, recipient, amount);

        uint256 currentAllowance = _allowances[sender][_msgSender()];
        require(currentAllowance >= amount, "ERC20: transfer amount exceeds allowance");
        _approve(sender, _msgSender(), currentAllowance - amount);

        return true;
    }

    /**
     * @dev Atomically increases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender] + addedValue);
        return true;
    }

    /**
     * @dev Atomically decreases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `spender` must have allowance for the caller of at least
     * `subtractedValue`.
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {
        uint256 currentAllowance = _allowances[_msgSender()][spender];
        require(currentAllowance >= subtractedValue, "ERC20: decreased allowance below zero");
        _approve(_msgSender(), spender, currentAllowance - subtractedValue);

        return true;
    }

    /**
     * @dev Moves tokens `amount` from `sender` to `recipient`.
     *
     * This is internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * Requirements:
     *
     * - `sender` cannot be the zero address.
     * - `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     */
    function _transfer(address sender, address recipient, uint256 amount) internal virtual {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(sender, recipient, amount);

        uint256 senderBalance = _balances[sender];
        require(senderBalance >= amount, "ERC20: transfer amount exceeds balance");
        _balances[sender] = senderBalance - amount;
        _balances[recipient] += amount;

        emit Transfer(sender, recipient, amount);
    }

    /** @dev Creates `amount` tokens and assigns them to `account`, increasing
     * the total supply.
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     */
    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: mint to the zero address");

        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply += amount;
        _balances[account] += amount;
        emit Transfer(address(0), account, amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`, reducing the
     * total supply.
     *
     * Emits a {Transfer} event with `to` set to the zero address.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     * - `account` must have at least `amount` tokens.
     */
    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: burn from the zero address");

        _beforeTokenTransfer(account, address(0), amount);

        uint256 accountBalance = _balances[account];
        require(accountBalance >= amount, "ERC20: burn amount exceeds balance");
        _balances[account] = accountBalance - amount;
        _totalSupply -= amount;

        emit Transfer(account, address(0), amount);
    }

    /**
     * @dev Sets `amount` as the allowance of `spender` over the `owner` s tokens.
     *
     * This internal function is equivalent to `approve`, and can be used to
     * e.g. set automatic allowances for certain subsystems, etc.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `owner` cannot be the zero address.
     * - `spender` cannot be the zero address.
     */
    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    /**
     * @dev Hook that is called before any transfer of tokens. This includes
     * minting and burning.
     *
     * Calling conditions:
     *
     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens
     * will be to transferred to `to`.
     * - when `from` is zero, `amount` tokens will be minted for `to`.
     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual { }
}


// File contracts/token/ERC20/extensions/ERC20Burnable.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Extension of {ERC20} that allows token holders to destroy both their own
 * tokens and those that they have an allowance for, in a way that can be
 * recognized off-chain (via event analysis).
 */
abstract contract ERC20Burnable is Context, ERC20 {
    /**
     * @dev Destroys `amount` tokens from the caller.
     *
     * See {ERC20-_burn}.
     */
    function burn(uint256 amount) public virtual {
        _burn(_msgSender(), amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`, deducting from the caller's
     * allowance.
     *
     * See {ERC20-_burn} and {ERC20-allowance}.
     *
     * Requirements:
     *
     * - the caller must have allowance for ``accounts``'s tokens of at least
     * `amount`.
     */
    function burnFrom(address account, uint256 amount) public virtual {
        uint256 currentAllowance = allowance(account, _msgSender());
        require(currentAllowance >= amount, "ERC20: burn amount exceeds allowance");
        _approve(account, _msgSender(), currentAllowance - amount);
        _burn(account, amount);
    }
}


// File contracts/mocks/ERC20BurnableMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC20BurnableMock is ERC20Burnable {
    constructor (
        string memory name,
        string memory symbol,
        address initialAccount,
        uint256 initialBalance
    ) ERC20(name, symbol) {
        _mint(initialAccount, initialBalance);
    }
}


// File contracts/token/ERC20/extensions/ERC20Capped.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Extension of {ERC20} that adds a cap to the supply of tokens.
 */
abstract contract ERC20Capped is ERC20 {
    uint256 immutable private _cap;

    /**
     * @dev Sets the value of the `cap`. This value is immutable, it can only be
     * set once during construction.
     */
    constructor (uint256 cap_) {
        require(cap_ > 0, "ERC20Capped: cap is 0");
        _cap = cap_;
    }

    /**
     * @dev Returns the cap on the token's total supply.
     */
    function cap() public view virtual returns (uint256) {
        return _cap;
    }

    /**
     * @dev See {ERC20-_mint}.
     */
    function _mint(address account, uint256 amount) internal virtual override {
        require(ERC20.totalSupply() + amount <= cap(), "ERC20Capped: cap exceeded");
        super._mint(account, amount);
    }
}


// File contracts/mocks/ERC20CappedMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC20CappedMock is ERC20Capped {
    constructor (string memory name, string memory symbol, uint256 cap)
        ERC20(name, symbol) ERC20Capped(cap)
    { }

    function mint(address to, uint256 tokenId) public {
        _mint(to, tokenId);
    }
}


// File contracts/mocks/ERC20DecimalsMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC20DecimalsMock is ERC20 {
    uint8 immutable private _decimals;

    constructor (string memory name_, string memory symbol_, uint8 decimals_) ERC20(name_, symbol_) {
        _decimals = decimals_;
    }

    function decimals() public view virtual override returns (uint8) {
        return _decimals;
    }
}


// File contracts/mocks/ERC20Mock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
// mock class using ERC20
contract ERC20Mock is ERC20 {
    constructor (
        string memory name,
        string memory symbol,
        address initialAccount,
        uint256 initialBalance
    ) payable ERC20(name, symbol) {
        _mint(initialAccount, initialBalance);
    }

    function mint(address account, uint256 amount) public {
        _mint(account, amount);
    }

    function burn(address account, uint256 amount) public {
        _burn(account, amount);
    }

    function transferInternal(address from, address to, uint256 value) public {
        _transfer(from, to, value);
    }

    function approveInternal(address owner, address spender, uint256 value) public {
        _approve(owner, spender, value);
    }
}


// File contracts/token/ERC20/extensions/ERC20Pausable.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev ERC20 token with pausable token transfers, minting and burning.
 *
 * Useful for scenarios such as preventing trades until the end of an evaluation
 * period, or having an emergency switch for freezing all token transfers in the
 * event of a large bug.
 */
abstract contract ERC20Pausable is ERC20, Pausable {
    /**
     * @dev See {ERC20-_beforeTokenTransfer}.
     *
     * Requirements:
     *
     * - the contract must not be paused.
     */
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual override {
        super._beforeTokenTransfer(from, to, amount);

        require(!paused(), "ERC20Pausable: token transfer while paused");
    }
}


// File contracts/mocks/ERC20PausableMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
// mock class using ERC20Pausable
contract ERC20PausableMock is ERC20Pausable {
    constructor (
        string memory name,
        string memory symbol,
        address initialAccount,
        uint256 initialBalance
    ) ERC20(name, symbol) {
        _mint(initialAccount, initialBalance);
    }

    function pause() external {
        _pause();
    }

    function unpause() external {
        _unpause();
    }

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }

    function burn(address from, uint256 amount) public {
        _burn(from, amount);
    }
}


// File contracts/token/ERC20/extensions/draft-IERC20Permit.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on `{IERC20-approve}`, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 */
interface IERC20Permit {
    /**
     * @dev Sets `value` as the allowance of `spender` over `owner`'s tokens,
     * given `owner`'s signed approval.
     *
     * IMPORTANT: The same issues {IERC20-approve} has related to transaction
     * ordering also apply here.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `deadline` must be a timestamp in the future.
     * - `v`, `r` and `s` must be a valid `secp256k1` signature from `owner`
     * over the EIP712-formatted function arguments.
     * - the signature must use ``owner``'s current nonce (see {nonces}).
     *
     * For more information on the signature format, see the
     * https://eips.ethereum.org/EIPS/eip-2612#specification[relevant EIP
     * section].
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;

    /**
     * @dev Returns the current nonce for `owner`. This value must be
     * included whenever a signature is generated for {permit}.
     *
     * Every successful call to {permit} increases ``owner``'s nonce by one. This
     * prevents a signature from being used multiple times.
     */
    function nonces(address owner) external view returns (uint256);

    /**
     * @dev Returns the domain separator used in the encoding of the signature for `permit`, as defined by {EIP712}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view returns (bytes32);
}


// File contracts/token/ERC20/extensions/draft-ERC20Permit.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Implementation of the ERC20 Permit extension allowing approvals to be made via signatures, as defined in
 * https://eips.ethereum.org/EIPS/eip-2612[EIP-2612].
 *
 * Adds the {permit} method, which can be used to change an account's ERC20 allowance (see {IERC20-allowance}) by
 * presenting a message signed by the account. By not relying on `{IERC20-approve}`, the token holder account doesn't
 * need to send a transaction, and thus is not required to hold Ether at all.
 *
 * _Available since v3.4._
 */
abstract contract ERC20Permit is ERC20, IERC20Permit, EIP712 {
    using Counters for Counters.Counter;

    mapping (address => Counters.Counter) private _nonces;

    // solhint-disable-next-line var-name-mixedcase
    bytes32 private immutable _PERMIT_TYPEHASH = keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    /**
     * @dev Initializes the {EIP712} domain separator using the `name` parameter, and setting `version` to `"1"`.
     *
     * It's a good idea to use the same `name` that is defined as the ERC20 token name.
     */
    constructor(string memory name) EIP712(name, "1") {
    }

    /**
     * @dev See {IERC20Permit-permit}.
     */
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) public virtual override {
        // solhint-disable-next-line not-rely-on-time
        require(block.timestamp <= deadline, "ERC20Permit: expired deadline");

        bytes32 structHash = keccak256(
            abi.encode(
                _PERMIT_TYPEHASH,
                owner,
                spender,
                value,
                _nonces[owner].current(),
                deadline
            )
        );

        bytes32 hash = _hashTypedDataV4(structHash);

        address signer = ECDSA.recover(hash, v, r, s);
        require(signer == owner, "ERC20Permit: invalid signature");

        _nonces[owner].increment();
        _approve(owner, spender, value);
    }

    /**
     * @dev See {IERC20Permit-nonces}.
     */
    function nonces(address owner) public view override returns (uint256) {
        return _nonces[owner].current();
    }

    /**
     * @dev See {IERC20Permit-DOMAIN_SEPARATOR}.
     */
    // solhint-disable-next-line func-name-mixedcase
    function DOMAIN_SEPARATOR() external view override returns (bytes32) {
        return _domainSeparatorV4();
    }
}


// File contracts/mocks/ERC20PermitMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC20PermitMock is ERC20Permit {
    constructor (
        string memory name,
        string memory symbol,
        address initialAccount,
        uint256 initialBalance
    ) payable ERC20(name, symbol) ERC20Permit(name) {
        _mint(initialAccount, initialBalance);
    }

    function getChainId() external view returns (uint256) {
        return block.chainid;
    }
}


// File contracts/token/ERC20/extensions/ERC20Snapshot.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev This contract extends an ERC20 token with a snapshot mechanism. When a snapshot is created, the balances and
 * total supply at the time are recorded for later access.
 *
 * This can be used to safely create mechanisms based on token balances such as trustless dividends or weighted voting.
 * In naive implementations it's possible to perform a "double spend" attack by reusing the same balance from different
 * accounts. By using snapshots to calculate dividends or voting power, those attacks no longer apply. It can also be
 * used to create an efficient ERC20 forking mechanism.
 *
 * Snapshots are created by the internal {_snapshot} function, which will emit the {Snapshot} event and return a
 * snapshot id. To get the total supply at the time of a snapshot, call the function {totalSupplyAt} with the snapshot
 * id. To get the balance of an account at the time of a snapshot, call the {balanceOfAt} function with the snapshot id
 * and the account address.
 *
 * ==== Gas Costs
 *
 * Snapshots are efficient. Snapshot creation is _O(1)_. Retrieval of balances or total supply from a snapshot is _O(log
 * n)_ in the number of snapshots that have been created, although _n_ for a specific account will generally be much
 * smaller since identical balances in subsequent snapshots are stored as a single entry.
 *
 * There is a constant overhead for normal ERC20 transfers due to the additional snapshot bookkeeping. This overhead is
 * only significant for the first transfer that immediately follows a snapshot for a particular account. Subsequent
 * transfers will have normal cost until the next snapshot, and so on.
 */
abstract contract ERC20Snapshot is ERC20 {
    // Inspired by Jordi Baylina's MiniMeToken to record historical balances:
    // https://github.com/Giveth/minimd/blob/ea04d950eea153a04c51fa510b068b9dded390cb/contracts/MiniMeToken.sol

    using Arrays for uint256[];
    using Counters for Counters.Counter;

    // Snapshotted values have arrays of ids and the value corresponding to that id. These could be an array of a
    // Snapshot struct, but that would impede usage of functions that work on an array.
    struct Snapshots {
        uint256[] ids;
        uint256[] values;
    }

    mapping (address => Snapshots) private _accountBalanceSnapshots;
    Snapshots private _totalSupplySnapshots;

    // Snapshot ids increase monotonically, with the first value being 1. An id of 0 is invalid.
    Counters.Counter private _currentSnapshotId;

    /**
     * @dev Emitted by {_snapshot} when a snapshot identified by `id` is created.
     */
    event Snapshot(uint256 id);

    /**
     * @dev Creates a new snapshot and returns its snapshot id.
     *
     * Emits a {Snapshot} event that contains the same id.
     *
     * {_snapshot} is `internal` and you have to decide how to expose it externally. Its usage may be restricted to a
     * set of accounts, for example using {AccessControl}, or it may be open to the public.
     *
     * [WARNING]
     * ====
     * While an open way of calling {_snapshot} is required for certain trust minimization mechanisms such as forking,
     * you must consider that it can potentially be used by attackers in two ways.
     *
     * First, it can be used to increase the cost of retrieval of values from snapshots, although it will grow
     * logarithmically thus rendering this attack ineffective in the long term. Second, it can be used to target
     * specific accounts and increase the cost of ERC20 transfers for them, in the ways specified in the Gas Costs
     * section above.
     *
     * We haven't measured the actual numbers; if this is something you're interested in please reach out to us.
     * ====
     */
    function _snapshot() internal virtual returns (uint256) {
        _currentSnapshotId.increment();

        uint256 currentId = _currentSnapshotId.current();
        emit Snapshot(currentId);
        return currentId;
    }

    /**
     * @dev Retrieves the balance of `account` at the time `snapshotId` was created.
     */
    function balanceOfAt(address account, uint256 snapshotId) public view virtual returns (uint256) {
        (bool snapshotted, uint256 value) = _valueAt(snapshotId, _accountBalanceSnapshots[account]);

        return snapshotted ? value : balanceOf(account);
    }

    /**
     * @dev Retrieves the total supply at the time `snapshotId` was created.
     */
    function totalSupplyAt(uint256 snapshotId) public view virtual returns(uint256) {
        (bool snapshotted, uint256 value) = _valueAt(snapshotId, _totalSupplySnapshots);

        return snapshotted ? value : totalSupply();
    }


    // Update balance and/or total supply snapshots before the values are modified. This is implemented
    // in the _beforeTokenTransfer hook, which is executed for _mint, _burn, and _transfer operations.
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual override {
      super._beforeTokenTransfer(from, to, amount);

      if (from == address(0)) {
        // mint
        _updateAccountSnapshot(to);
        _updateTotalSupplySnapshot();
      } else if (to == address(0)) {
        // burn
        _updateAccountSnapshot(from);
        _updateTotalSupplySnapshot();
      } else {
        // transfer
        _updateAccountSnapshot(from);
        _updateAccountSnapshot(to);
      }
    }

    function _valueAt(uint256 snapshotId, Snapshots storage snapshots)
        private view returns (bool, uint256)
    {
        require(snapshotId > 0, "ERC20Snapshot: id is 0");
        // solhint-disable-next-line max-line-length
        require(snapshotId <= _currentSnapshotId.current(), "ERC20Snapshot: nonexistent id");

        // When a valid snapshot is queried, there are three possibilities:
        //  a) The queried value was not modified after the snapshot was taken. Therefore, a snapshot entry was never
        //  created for this id, and all stored snapshot ids are smaller than the requested one. The value that corresponds
        //  to this id is the current one.
        //  b) The queried value was modified after the snapshot was taken. Therefore, there will be an entry with the
        //  requested id, and its value is the one to return.
        //  c) More snapshots were created after the requested one, and the queried value was later modified. There will be
        //  no entry for the requested id: the value that corresponds to it is that of the smallest snapshot id that is
        //  larger than the requested one.
        //
        // In summary, we need to find an element in an array, returning the index of the smallest value that is larger if
        // it is not found, unless said value doesn't exist (e.g. when all values are smaller). Arrays.findUpperBound does
        // exactly this.

        uint256 index = snapshots.ids.findUpperBound(snapshotId);

        if (index == snapshots.ids.length) {
            return (false, 0);
        } else {
            return (true, snapshots.values[index]);
        }
    }

    function _updateAccountSnapshot(address account) private {
        _updateSnapshot(_accountBalanceSnapshots[account], balanceOf(account));
    }

    function _updateTotalSupplySnapshot() private {
        _updateSnapshot(_totalSupplySnapshots, totalSupply());
    }

    function _updateSnapshot(Snapshots storage snapshots, uint256 currentValue) private {
        uint256 currentId = _currentSnapshotId.current();
        if (_lastSnapshotId(snapshots.ids) < currentId) {
            snapshots.ids.push(currentId);
            snapshots.values.push(currentValue);
        }
    }

    function _lastSnapshotId(uint256[] storage ids) private view returns (uint256) {
        if (ids.length == 0) {
            return 0;
        } else {
            return ids[ids.length - 1];
        }
    }
}


// File contracts/mocks/ERC20SnapshotMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC20SnapshotMock is ERC20Snapshot {
    constructor(
        string memory name,
        string memory symbol,
        address initialAccount,
        uint256 initialBalance
    ) ERC20(name, symbol) {
        _mint(initialAccount, initialBalance);
    }

    function snapshot() public {
        _snapshot();
    }

    function mint(address account, uint256 amount) public {
        _mint(account, amount);
    }

    function burn(address account, uint256 amount) public {
        _burn(account, amount);
    }
}


// File contracts/mocks/ERC2771ContextMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
// By inheriting from ERC2771Context, Context's internal functions are overridden automatically
contract ERC2771ContextMock is ContextMock, ERC2771Context {
    constructor(address trustedForwarder) ERC2771Context(trustedForwarder) {}

    function _msgSender() internal override(Context, ERC2771Context) view virtual returns (address) {
        return ERC2771Context._msgSender();
    }

    function _msgData() internal override(Context, ERC2771Context) view virtual returns (bytes calldata) {
        return ERC2771Context._msgData();
    }
}


// File contracts/utils/Strings.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev String operations.
 */
library Strings {
    bytes16 private constant alphabet = "0123456789abcdef";

    /**
     * @dev Converts a `uint256` to its ASCII `string` decimal representation.
     */
    function toString(uint256 value) internal pure returns (string memory) {
        // Inspired by OraclizeAPI's implementation - MIT licence
        // https://github.com/oraclize/ethereum-api/blob/b42146b063c7d6ee1358846c198246239e9360e8/oraclizeAPI_0.4.25.sol

        if (value == 0) {
            return "0";
        }
        uint256 temp = value;
        uint256 digits;
        while (temp != 0) {
            digits++;
            temp /= 10;
        }
        bytes memory buffer = new bytes(digits);
        while (value != 0) {
            digits -= 1;
            buffer[digits] = bytes1(uint8(48 + uint256(value % 10)));
            value /= 10;
        }
        return string(buffer);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation.
     */
    function toHexString(uint256 value) internal pure returns (string memory) {
        if (value == 0) {
            return "0x00";
        }
        uint256 temp = value;
        uint256 length = 0;
        while (temp != 0) {
            length++;
            temp >>= 8;
        }
        return toHexString(value, length);
    }

    /**
     * @dev Converts a `uint256` to its ASCII `string` hexadecimal representation with fixed length.
     */
    function toHexString(uint256 value, uint256 length) internal pure returns (string memory) {
        bytes memory buffer = new bytes(2 * length + 2);
        buffer[0] = "0";
        buffer[1] = "x";
        for (uint256 i = 2 * length + 1; i > 1; --i) {
            buffer[i] = alphabet[value & 0xf];
            value >>= 4;
        }
        require(value == 0, "Strings: hex length insufficient");
        return string(buffer);
    }

}


// File contracts/token/ERC721/IERC721.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Required interface of an ERC721 compliant contract.
 */
interface IERC721 is IERC165 {
    /**
     * @dev Emitted when `tokenId` token is transferred from `from` to `to`.
     */
    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables `approved` to manage the `tokenId` token.
     */
    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);

    /**
     * @dev Emitted when `owner` enables or disables (`approved`) `operator` to manage all of its assets.
     */
    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);

    /**
     * @dev Returns the number of tokens in ``owner``'s account.
     */
    function balanceOf(address owner) external view returns (uint256 balance);

    /**
     * @dev Returns the owner of the `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function ownerOf(uint256 tokenId) external view returns (address owner);

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If the caller is not `from`, it must be have been allowed to move this token by either {approve} or {setApprovalForAll}.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId) external payable;

    /**
     * @dev Transfers `tokenId` token from `from` to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {safeTransferFrom} whenever possible.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address from, address to, uint256 tokenId) external;

    /**
     * @dev Gives permission to `to` to transfer `tokenId` token to another account.
     * The approval is cleared when the token is transferred.
     *
     * Only a single account can be approved at a time, so approving the zero address clears previous approvals.
     *
     * Requirements:
     *
     * - The caller must own the token or be an approved operator.
     * - `tokenId` must exist.
     *
     * Emits an {Approval} event.
     */
    function approve(address to, uint256 tokenId) external;

    /**
     * @dev Returns the account approved for `tokenId` token.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function getApproved(uint256 tokenId) external view returns (address operator);

    /**
     * @dev Approve or remove `operator` as an operator for the caller.
     * Operators can call {transferFrom} or {safeTransferFrom} for any token owned by the caller.
     *
     * Requirements:
     *
     * - The `operator` cannot be the caller.
     *
     * Emits an {ApprovalForAll} event.
     */
    function setApprovalForAll(address operator, bool _approved) external;

    /**
     * @dev Returns if the `operator` is allowed to manage all of the assets of `owner`.
     *
     * See {setApprovalForAll}
     */
    function isApprovedForAll(address owner, address operator) external view returns (bool);

    /**
      * @dev Safely transfers `tokenId` token from `from` to `to`.
      *
      * Requirements:
      *
      * - `from` cannot be the zero address.
      * - `to` cannot be the zero address.
      * - `tokenId` token must exist and be owned by `from`.
      * - If the caller is not `from`, it must be approved to move this token by either {approve} or {setApprovalForAll}.
      * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
      *
      * Emits a {Transfer} event.
      */
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes calldata data) external payable;
}


// File contracts/token/ERC721/IERC721Receiver.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @title ERC721 token receiver interface
 * @dev Interface for any contract that wants to support safeTransfers
 * from ERC721 asset contracts.
 */
interface IERC721Receiver {
    /**
     * @dev Whenever an {IERC721} `tokenId` token is transferred to this contract via {IERC721-safeTransferFrom}
     * by `operator` from `from`, this function is called.
     *
     * It must return its Solidity selector to confirm the token transfer.
     * If any other value is returned or the interface is not implemented by the recipient, the transfer will be reverted.
     *
     * The selector can be obtained in Solidity with `IERC721.onERC721Received.selector`.
     */
    function onERC721Received(address operator, address from, uint256 tokenId, bytes calldata data) external returns (bytes4);
}


// File contracts/token/ERC721/extensions/IERC721Metadata.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title ERC-721 Non-Fungible Token Standard, optional metadata extension
 * @dev See https://eips.ethereum.org/EIPS/eip-721
 */
interface IERC721Metadata is IERC721 {

    /**
     * @dev Returns the token collection name.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the token collection symbol.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the Uniform Resource Identifier (URI) for `tokenId` token.
     */
    function tokenURI(uint256 tokenId) external view returns (string memory);
}


// File contracts/token/ERC721/extensions/IERC721Enumerable.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title ERC-721 Non-Fungible Token Standard, optional enumeration extension
 * @dev See https://eips.ethereum.org/EIPS/eip-721
 */
interface IERC721Enumerable is IERC721 {

    /**
     * @dev Returns the total amount of tokens stored by the contract.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns a token ID owned by `owner` at a given `index` of its token list.
     * Use along with {balanceOf} to enumerate all of ``owner``'s tokens.
     */
    function tokenOfOwnerByIndex(address owner, uint256 index) external view returns (uint256 tokenId);

    /**
     * @dev Returns a token ID at a given `index` of all the tokens stored by the contract.
     * Use along with {totalSupply} to enumerate all tokens.
     */
    function tokenByIndex(uint256 index) external view returns (uint256);
}


// File contracts/token/ERC721/ERC721.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Implementation of https://eips.ethereum.org/EIPS/eip-721[ERC721] Non-Fungible Token Standard, including
 * the Metadata extension, but not including the Enumerable extension, which is available separately as
 * {ERC721Enumerable}.
 */
contract ERC721 is Ownable, ERC165, IERC721, IERC721Metadata {
    using Address for address;
    using Strings for uint256;

    // Token name
    string private _name;

    // Token symbol
    string private _symbol;

    // Mapping from token ID to owner address
    mapping (uint256 => address) private _owners;

    // Mapping owner address to token count
    mapping (address => uint256) private _balances;

    // Mapping from token ID to approved address
    mapping (uint256 => address) private _tokenApprovals;

    // Mapping from owner to operator approvals
    mapping (address => mapping (address => bool)) private _operatorApprovals;

    /**
     * @dev Initializes the contract by setting a `name` and a `symbol` to the token collection.
     */
    constructor (string memory name_, string memory symbol_) {
        _name = name_;
        _symbol = symbol_;
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IERC721).interfaceId
            || interfaceId == type(IERC721Metadata).interfaceId
            || super.supportsInterface(interfaceId);
    }

    /**
     * @dev See {IERC721-balanceOf}.
     */
    function balanceOf(address owner) public view virtual override returns (uint256) {
        require(owner != address(0), "ERC721: balance query for the zero address");
        return _balances[owner];
    }

    /**
     * @dev See {IERC721-ownerOf}.
     */
    function ownerOf(uint256 tokenId) public view virtual override returns (address) {
        address owner = _owners[tokenId];
        require(owner != address(0), "ERC721: owner query for nonexistent token");
        return owner;
    }

    /**
     * @dev See {IERC721Metadata-name}.
     */
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /**
     * @dev See {IERC721Metadata-symbol}.
     */
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "ERC721Metadata: URI query for nonexistent token");

        string memory baseURI = _baseURI();
        return bytes(baseURI).length > 0
            ? string(abi.encodePacked(baseURI, tokenId.toString()))
            : '';
    }

    /**
     * @dev Base URI for computing {tokenURI}. Empty by default, can be overriden
     * in child contracts.
     */
    function _baseURI() internal view virtual returns (string memory) {
        return "";
    }

    /**
     * @dev See {IERC721-approve}.
     */
    function approve(address to, uint256 tokenId) public virtual override {
        address owner = ERC721.ownerOf(tokenId);
        require(to != owner, "ERC721: approval to current owner");

        require(_msgSender() == owner || ERC721.isApprovedForAll(owner, _msgSender()),
            "ERC721: approve caller is not owner nor approved for all"
        );

        _approve(to, tokenId);
    }

    /**
     * @dev See {IERC721-getApproved}.
     */
    function getApproved(uint256 tokenId) public view virtual override returns (address) {
        require(_exists(tokenId), "ERC721: approved query for nonexistent token");

        return _tokenApprovals[tokenId];
    }

    /**
     * @dev See {IERC721-setApprovalForAll}.
     */
    function setApprovalForAll(address operator, bool approved) public virtual override {
        require(operator != _msgSender(), "ERC721: approve to caller");

        _operatorApprovals[_msgSender()][operator] = approved;
        emit ApprovalForAll(_msgSender(), operator, approved);
    }

    /**
     * @dev See {IERC721-isApprovedForAll}.
     */
    function isApprovedForAll(address owner, address operator) public view virtual override returns (bool) {
        return _operatorApprovals[owner][operator];
    }

    /**
     * @dev See {IERC721-transferFrom}.
     */
    function transferFrom(address from, address to, uint256 tokenId) public virtual override {
        //solhint-disable-next-line max-line-length
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");

        _transfer(from, to, tokenId);
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId) public virtual payable override {
        safeTransferFrom(from, to, tokenId, "");
    }

    /**
     * @dev See {IERC721-safeTransferFrom}.
     */
    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public virtual payable override {
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721: transfer caller is not owner nor approved");
        _safeTransfer(from, to, tokenId, _data);
    }

    /**
     * @dev Safely transfers `tokenId` token from `from` to `to`, checking first that contract recipients
     * are aware of the ERC721 protocol to prevent tokens from being forever locked.
     *
     * `_data` is additional data, it has no specified format and it is sent in call to `to`.
     *
     * This internal function is equivalent to {safeTransferFrom}, and can be used to e.g.
     * implement alternative mechanisms to perform token transfer, such as signature-based.
     *
     * Requirements:
     *
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     * - `tokenId` token must exist and be owned by `from`.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function _safeTransfer(address from, address to, uint256 tokenId, bytes memory _data) internal virtual {
        _transfer(from, to, tokenId);
        require(_checkOnERC721Received(from, to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }

    /**
     * @dev Returns whether `tokenId` exists.
     *
     * Tokens can be managed by their owner or approved accounts via {approve} or {setApprovalForAll}.
     *
     * Tokens start existing when they are minted (`_mint`),
     * and stop existing when they are burned (`_burn`).
     */
    function _exists(uint256 tokenId) internal view virtual returns (bool) {
        return _owners[tokenId] != address(0);
    }

    /**
     * @dev Returns whether `spender` is allowed to manage `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view virtual returns (bool) {
        require(_exists(tokenId), "ERC721: operator query for nonexistent token");
        address owner = ERC721.ownerOf(tokenId);
        return (spender == owner || getApproved(tokenId) == spender || ERC721.isApprovedForAll(owner, spender));
    }

    /**
     * @dev Safely mints `tokenId` and transfers it to `to`.
     *
     * Requirements:
     d*
     * - `tokenId` must not exist.
     * - If `to` refers to a smart contract, it must implement {IERC721Receiver-onERC721Received}, which is called upon a safe transfer.
     *
     * Emits a {Transfer} event.
     */
    function _safeMint(address to, uint256 tokenId) internal virtual {
        _safeMint(to, tokenId, "");
    }

    /**
     * @dev Same as {xref-ERC721-_safeMint-address-uint256-}[`_safeMint`], with an additional `data` parameter which is
     * forwarded in {IERC721Receiver-onERC721Received} to contract recipients.
     */
    function _safeMint(address to, uint256 tokenId, bytes memory _data) internal virtual {
        _mint(to, tokenId);
        require(_checkOnERC721Received(address(0), to, tokenId, _data), "ERC721: transfer to non ERC721Receiver implementer");
    }

    /**
     * @dev Mints `tokenId` and transfers it to `to`.
     *
     * WARNING: Usage of this method is discouraged, use {_safeMint} whenever possible
     *
     * Requirements:
     *
     * - `tokenId` must not exist.
     * - `to` cannot be the zero address.
     *
     * Emits a {Transfer} event.
     */
    function _mint(address to, uint256 tokenId) internal virtual {
        require(to != address(0), "ERC721: mint to the zero address");
        require(!_exists(tokenId), "ERC721: token already minted");

        _beforeTokenTransfer(address(0), to, tokenId);

        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(address(0), to, tokenId);
    }

    /**
     * @dev Destroys `tokenId`.
     * The approval is cleared when the token is burned.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     *
     * Emits a {Transfer} event.
     */
    function _burn(uint256 tokenId) internal virtual {
        address owner = ERC721.ownerOf(tokenId);

        _beforeTokenTransfer(owner, address(0), tokenId);

        // Clear approvals
        _approve(address(0), tokenId);

        _balances[owner] -= 1;
        delete _owners[tokenId];

        emit Transfer(owner, address(0), tokenId);
    }

    /**
     * @dev Transfers `tokenId` from `from` to `to`.
     *  As opposed to {transferFrom}, this imposes no restrictions on msg.sender.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     * - `tokenId` token must be owned by `from`.
     *
     * Emits a {Transfer} event.
     */
    function _transfer(address from, address to, uint256 tokenId) internal virtual {
        require(ERC721.ownerOf(tokenId) == from, "ERC721: transfer of token that is not own");
        require(to != address(0), "ERC721: transfer to the zero address");

        _beforeTokenTransfer(from, to, tokenId);

        // Clear approvals from the previous owner
        _approve(address(0), tokenId);

        _balances[from] -= 1;
        _balances[to] += 1;
        _owners[tokenId] = to;

        emit Transfer(from, to, tokenId);
    }

    /**
     * @dev Approve `to` to operate on `tokenId`
     *
     * Emits a {Approval} event.
     */
    function _approve(address to, uint256 tokenId) internal virtual {
        _tokenApprovals[tokenId] = to;
        emit Approval(ERC721.ownerOf(tokenId), to, tokenId);
    }

    /**
     * @dev Internal function to invoke {IERC721Receiver-onERC721Received} on a target address.
     * The call is not executed if the target address is not a contract.
     *
     * @param from address representing the previous owner of the given token ID
     * @param to target address that will receive the tokens
     * @param tokenId uint256 ID of the token to be transferred
     * @param _data bytes optional data to send along with the call
     * @return bool whether the call correctly returned the expected magic value
     */
    function _checkOnERC721Received(address from, address to, uint256 tokenId, bytes memory _data)
        private returns (bool)
    {
        if (to.isContract()) {
            try IERC721Receiver(to).onERC721Received(_msgSender(), from, tokenId, _data) returns (bytes4 retval) {
                return retval == IERC721Receiver(to).onERC721Received.selector;
            } catch (bytes memory reason) {
                if (reason.length == 0) {
                    revert("ERC721: transfer to non ERC721Receiver implementer");
                } else {
                    // solhint-disable-next-line no-inline-assembly
                    assembly {
                        revert(add(32, reason), mload(reason))
                    }
                }
            }
        } else {
            return true;
        }
    }

    /**
     * @dev Hook that is called before any token transfer. This includes minting
     * and burning.
     *
     * Calling conditions:
     *
     * - When `from` and `to` are both non-zero, ``from``'s `tokenId` will be
     * transferred to `to`.
     * - When `from` is zero, `tokenId` will be minted for `to`.
     * - When `to` is zero, ``from``'s `tokenId` will be burned.
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(address from, address to, uint256 tokenId) internal virtual { }
}


// File contracts/token/ERC721/extensions/ERC721Burnable.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title ERC721 Burnable Token
 * @dev ERC721 Token that can be irreversibly burned (destroyed).
 */
abstract contract ERC721Burnable is Context, ERC721 {
    /**
     * @dev Burns `tokenId`. See {ERC721-_burn}.
     *
     * Requirements:
     *
     * - The caller must own `tokenId` or be an approved operator.
     */
    function burn(uint256 tokenId) public virtual {
        //solhint-disable-next-line max-line-length
        require(_isApprovedOrOwner(_msgSender(), tokenId), "ERC721Burnable: caller is not owner nor approved");
        _burn(tokenId);
    }
}


// File contracts/mocks/ERC721BurnableMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC721BurnableMock is ERC721Burnable {
    constructor(string memory name, string memory symbol) ERC721(name, symbol) { }

    function exists(uint256 tokenId) public view returns (bool) {
        return _exists(tokenId);
    }

    function mint(address to, uint256 tokenId) public {
        _mint(to, tokenId);
    }

    function safeMint(address to, uint256 tokenId) public {
        _safeMint(to, tokenId);
    }

    function safeMint(address to, uint256 tokenId, bytes memory _data) public {
        _safeMint(to, tokenId, _data);
    }
}


// File contracts/token/ERC721/extensions/ERC721Enumerable.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev This implements an optional extension of {ERC721} defined in the EIP that adds
 * enumerability of all the token ids in the contract as well as all token ids owned by each
 * account.
 */
abstract contract ERC721Enumerable is ERC721, IERC721Enumerable {
    // Mapping from owner to list of owned token IDs
    mapping(address => mapping(uint256 => uint256)) private _ownedTokens;

    // Mapping from token ID to index of the owner tokens list
    mapping(uint256 => uint256) private _ownedTokensIndex;

    // Array with all token ids, used for enumeration
    uint256[] private _allTokens;

    // Mapping from token id to position in the allTokens array
    mapping(uint256 => uint256) private _allTokensIndex;

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(IERC165, ERC721) returns (bool) {
        return interfaceId == type(IERC721Enumerable).interfaceId
            || super.supportsInterface(interfaceId);
    }

    /**
     * @dev See {IERC721Enumerable-tokenOfOwnerByIndex}.
     */
    function tokenOfOwnerByIndex(address owner, uint256 index) public view virtual override returns (uint256) {
        require(index < ERC721.balanceOf(owner), "ERC721Enumerable: owner index out of bounds");
        return _ownedTokens[owner][index];
    }

    function tokensOfOwner(address owner) public view returns (uint256[] memory) {
        uint256[] memory memoryArray = new uint256[](ERC721.balanceOf(owner));
        for(uint i = 0; i < ERC721.balanceOf(owner); i++) {
            memoryArray[i] = _ownedTokens[owner][i];
        }
        return memoryArray;
    }

    /**
     * @dev See {IERC721Enumerable-totalSupply}.
     */
    function totalSupply() public view virtual override returns (uint256) {
        return _allTokens.length;
    }

    /**
     * @dev See {IERC721Enumerable-tokenByIndex}.
     */
    function tokenByIndex(uint256 index) public view virtual override returns (uint256) {
        require(index < ERC721Enumerable.totalSupply(), "ERC721Enumerable: global index out of bounds");
        return _allTokens[index];
    }

    /**
     * @dev Hook that is called before any token transfer. This includes minting
     * and burning.
     *
     * Calling conditions:
     *
     * - When `from` and `to` are both non-zero, ``from``'s `tokenId` will be
     * transferred to `to`.
     * - When `from` is zero, `tokenId` will be minted for `to`.
     * - When `to` is zero, ``from``'s `tokenId` will be burned.
     * - `from` cannot be the zero address.
     * - `to` cannot be the zero address.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(address from, address to, uint256 tokenId) internal virtual override {
        super._beforeTokenTransfer(from, to, tokenId);

        if (from == address(0)) {
            _addTokenToAllTokensEnumeration(tokenId);
        } else if (from != to) {
            _removeTokenFromOwnerEnumeration(from, tokenId);
        }
        if (to == address(0)) {
            _removeTokenFromAllTokensEnumeration(tokenId);
        } else if (to != from) {
            _addTokenToOwnerEnumeration(to, tokenId);
        }
    }

    /**
     * @dev Private function to add a token to this extension's ownership-tracking data structures.
     * @param to address representing the new owner of the given token ID
     * @param tokenId uint256 ID of the token to be added to the tokens list of the given address
     */
    function _addTokenToOwnerEnumeration(address to, uint256 tokenId) private {
        uint256 length = ERC721.balanceOf(to);
        _ownedTokens[to][length] = tokenId;
        _ownedTokensIndex[tokenId] = length;
    }

    /**
     * @dev Private function to add a token to this extension's token tracking data structures.
     * @param tokenId uint256 ID of the token to be added to the tokens list
     */
    function _addTokenToAllTokensEnumeration(uint256 tokenId) private {
        _allTokensIndex[tokenId] = _allTokens.length;
        _allTokens.push(tokenId);
    }

    /**
     * @dev Private function to remove a token from this extension's ownership-tracking data structures. Note that
     * while the token is not assigned a new owner, the `_ownedTokensIndex` mapping is _not_ updated: this allows for
     * gas optimizations e.g. when performing a transfer operation (avoiding double writes).
     * This has O(1) time complexity, but alters the order of the _ownedTokens array.
     * @param from address representing the previous owner of the given token ID
     * @param tokenId uint256 ID of the token to be removed from the tokens list of the given address
     */
    function _removeTokenFromOwnerEnumeration(address from, uint256 tokenId) private {
        // To prevent a gap in from's tokens array, we store the last token in the index of the token to delete, and
        // then delete the last slot (swap and pop).

        uint256 lastTokenIndex = ERC721.balanceOf(from) - 1;
        uint256 tokenIndex = _ownedTokensIndex[tokenId];

        // When the token to delete is the last token, the swap operation is unnecessary
        if (tokenIndex != lastTokenIndex) {
            uint256 lastTokenId = _ownedTokens[from][lastTokenIndex];

            _ownedTokens[from][tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token
            _ownedTokensIndex[lastTokenId] = tokenIndex; // Update the moved token's index
        }

        // This also deletes the contents at the last position of the array
        delete _ownedTokensIndex[tokenId];
        delete _ownedTokens[from][lastTokenIndex];
    }

    /**
     * @dev Private function to remove a token from this extension's token tracking data structures.
     * This has O(1) time complexity, but alters the order of the _allTokens array.
     * @param tokenId uint256 ID of the token to be removed from the tokens list
     */
    function _removeTokenFromAllTokensEnumeration(uint256 tokenId) private {
        // To prevent a gap in the tokens array, we store the last token in the index of the token to delete, and
        // then delete the last slot (swap and pop).

        uint256 lastTokenIndex = _allTokens.length - 1;
        uint256 tokenIndex = _allTokensIndex[tokenId];

        // When the token to delete is the last token, the swap operation is unnecessary. However, since this occurs so
        // rarely (when the last minted token is burnt) that we still do the swap here to avoid the gas cost of adding
        // an 'if' statement (like in _removeTokenFromOwnerEnumeration)
        uint256 lastTokenId = _allTokens[lastTokenIndex];

        _allTokens[tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token
        _allTokensIndex[lastTokenId] = tokenIndex; // Update the moved token's index

        // This also deletes the contents at the last position of the array
        delete _allTokensIndex[tokenId];
        _allTokens.pop();
    }
}


// File contracts/mocks/ERC721EnumerableMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title ERC721Mock
 * This mock just provides a public safeMint, mint, and burn functions for testing purposes
 */
contract ERC721EnumerableMock is ERC721Enumerable {
    string private _baseTokenURI;

    constructor (string memory name, string memory symbol) ERC721(name, symbol) { }

    function _baseURI() internal view virtual override returns (string memory) {
        return _baseTokenURI;
    }

    function setBaseURI(string calldata newBaseTokenURI) public {
        _baseTokenURI = newBaseTokenURI;
    }

    function baseURI() public view returns (string memory) {
        return _baseURI();
    }

    function exists(uint256 tokenId) public view returns (bool) {
        return _exists(tokenId);
    }

    function mint(address to, uint256 tokenId) public {
        _mint(to, tokenId);
    }

    function safeMint(address to, uint256 tokenId) public {
        _safeMint(to, tokenId);
    }

    function safeMint(address to, uint256 tokenId, bytes memory _data) public {
        _safeMint(to, tokenId, _data);
    }

    function burn(uint256 tokenId) public {
        _burn(tokenId);
    }
}


// File contracts/mocks/ERC721Mock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title ERC721Mock
 * This mock just provides a public safeMint, mint, and burn functions for testing purposes
 */
contract ERC721Mock is ERC721 {
    string private _baseTokenURI;

    constructor (string memory name, string memory symbol) ERC721(name, symbol) { }

    function _baseURI() internal view virtual override returns (string memory) {
        return _baseTokenURI;
    }

    function setBaseURI(string calldata newBaseTokenURI) public {
        _baseTokenURI = newBaseTokenURI;
    }

    function baseURI() public view returns (string memory) {
        return _baseURI();
    }

    function exists(uint256 tokenId) public view returns (bool) {
        return _exists(tokenId);
    }

    function mint(address to, uint256 tokenId) public {
        _mint(to, tokenId);
    }

    function safeMint(address to, uint256 tokenId) public {
        _safeMint(to, tokenId);
    }

    function safeMint(address to, uint256 tokenId, bytes memory _data) public {
        _safeMint(to, tokenId, _data);
    }

    function burn(uint256 tokenId) public {
        _burn(tokenId);
    }
}


// File contracts/token/ERC721/extensions/ERC721Pausable.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev ERC721 token with pausable token transfers, minting and burning.
 *
 * Useful for scenarios such as preventing trades until the end of an evaluation
 * period, or having an emergency switch for freezing all token transfers in the
 * event of a large bug.
 */
abstract contract ERC721Pausable is ERC721, Pausable {
    /**
     * @dev See {ERC721-_beforeTokenTransfer}.
     *
     * Requirements:
     *
     * - the contract must not be paused.
     */
    function _beforeTokenTransfer(address from, address to, uint256 tokenId) internal virtual override {
        super._beforeTokenTransfer(from, to, tokenId);

        require(!paused(), "ERC721Pausable: token transfer while paused");
    }
}


// File contracts/mocks/ERC721PausableMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title ERC721PausableMock
 * This mock just provides a public mint, burn and exists functions for testing purposes
 */
contract ERC721PausableMock is ERC721Pausable {
    constructor (string memory name, string memory symbol) ERC721(name, symbol) { }

    function pause() external {
        _pause();
    }

    function unpause() external {
        _unpause();
    }

    function exists(uint256 tokenId) public view returns (bool) {
        return _exists(tokenId);
    }

    function mint(address to, uint256 tokenId) public {
        _mint(to, tokenId);
    }

    function safeMint(address to, uint256 tokenId) public {
        _safeMint(to, tokenId);
    }

    function safeMint(address to, uint256 tokenId, bytes memory _data) public {
        _safeMint(to, tokenId, _data);
    }

    function burn(uint256 tokenId) public {
        _burn(tokenId);
    }
}


// File contracts/mocks/ERC721ReceiverMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC721ReceiverMock is IERC721Receiver {
    enum Error {
        None,
        RevertWithMessage,
        RevertWithoutMessage,
        Panic
    }

    bytes4 private immutable _retval;
    Error private immutable _error;

    event Received(address operator, address from, uint256 tokenId, bytes data, uint256 gas);

    constructor (bytes4 retval, Error error) {
        _retval = retval;
        _error = error;
    }

    function onERC721Received(address operator, address from, uint256 tokenId, bytes memory data)
        public override returns (bytes4)
    {
        if (_error == Error.RevertWithMessage) {
            revert("ERC721ReceiverMock: reverting");
        } else if (_error == Error.RevertWithoutMessage) {
            revert();
        } else if (_error == Error.Panic) {
            uint256 a = uint256(0) / uint256(0);
            a;
        }
        emit Received(operator, from, tokenId, data, gasleft());
        return _retval;
    }
}


// File contracts/token/ERC721/extensions/ERC721URIStorage.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev ERC721 token with storage based token uri management.
 */
abstract contract ERC721URIStorage is ERC721 {
    using Strings for uint256;

    // Optional mapping for token URIs
    mapping (uint256 => string) private _tokenURIs;

    /**
     * @dev See {IERC721Metadata-tokenURI}.
     */
    function tokenURI(uint256 tokenId) public view virtual override returns (string memory) {
        require(_exists(tokenId), "ERC721URIStorage: URI query for nonexistent token");

        string memory _tokenURI = _tokenURIs[tokenId];
        string memory base = _baseURI();

        // If there is no base URI, return the token URI.
        if (bytes(base).length == 0) {
            return _tokenURI;
        }
        // If both are set, concatenate the baseURI and tokenURI (via abi.encodePacked).
        if (bytes(_tokenURI).length > 0) {
            return string(abi.encodePacked(base, _tokenURI));
        }

        return super.tokenURI(tokenId);
    }

    /**
     * @dev Sets `_tokenURI` as the tokenURI of `tokenId`.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     */
    function _setTokenURI(uint256 tokenId, string memory _tokenURI) internal virtual {
        require(_exists(tokenId), "ERC721URIStorage: URI set of nonexistent token");
        _tokenURIs[tokenId] = _tokenURI;
    }

    /**
     * @dev Destroys `tokenId`.
     * The approval is cleared when the token is burned.
     *
     * Requirements:
     *
     * - `tokenId` must exist.
     *
     * Emits a {Transfer} event.
     */
    function _burn(uint256 tokenId) internal virtual override {
        super._burn(tokenId);

        if (bytes(_tokenURIs[tokenId]).length != 0) {
            delete _tokenURIs[tokenId];
        }
    }
}


// File contracts/mocks/ERC721URIStorageMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title ERC721Mock
 * This mock just provides a public safeMint, mint, and burn functions for testing purposes
 */
contract ERC721URIStorageMock is ERC721URIStorage {
    string private _baseTokenURI;

    constructor (string memory name, string memory symbol) ERC721(name, symbol) { }

    function _baseURI() internal view virtual override returns (string memory) {
        return _baseTokenURI;
    }

    function setBaseURI(string calldata newBaseTokenURI) public {
        _baseTokenURI = newBaseTokenURI;
    }

    function baseURI() public view returns (string memory) {
        return _baseURI();
    }

    function setTokenURI(uint256 tokenId, string memory _tokenURI) public {
        _setTokenURI(tokenId, _tokenURI);
    }

    function exists(uint256 tokenId) public view returns (bool) {
        return _exists(tokenId);
    }

    function mint(address to, uint256 tokenId) public {
        _mint(to, tokenId);
    }

    function safeMint(address to, uint256 tokenId) public {
        _safeMint(to, tokenId);
    }

    function safeMint(address to, uint256 tokenId, bytes memory _data) public {
        _safeMint(to, tokenId, _data);
    }

    function burn(uint256 tokenId) public {
        _burn(tokenId);
    }
}


// File contracts/utils/introspection/IERC1820Registry.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Interface of the global ERC1820 Registry, as defined in the
 * https://eips.ethereum.org/EIPS/eip-1820[EIP]. Accounts may register
 * implementers for interfaces in this registry, as well as query support.
 *
 * Implementers may be shared by multiple accounts, and can also implement more
 * than a single interface for each account. Contracts can implement interfaces
 * for themselves, but externally-owned accounts (EOA) must delegate this to a
 * contract.
 *
 * {IERC165} interfaces can also be queried via the registry.
 *
 * For an in-depth explanation and source code analysis, see the EIP text.
 */
interface IERC1820Registry {
    /**
     * @dev Sets `newManager` as the manager for `account`. A manager of an
     * account is able to set interface implementers for it.
     *
     * By default, each account is its own manager. Passing a value of `0x0` in
     * `newManager` will reset the manager to this initial state.
     *
     * Emits a {ManagerChanged} event.
     *
     * Requirements:
     *
     * - the caller must be the current manager for `account`.
     */
    function setManager(address account, address newManager) external;

    /**
     * @dev Returns the manager for `account`.
     *
     * See {setManager}.
     */
    function getManager(address account) external view returns (address);

    /**
     * @dev Sets the `implementer` contract as ``account``'s implementer for
     * `interfaceHash`.
     *
     * `account` being the zero address is an alias for the caller's address.
     * The zero address can also be used in `implementer` to remove an old one.
     *
     * See {interfaceHash} to learn how these are created.
     *
     * Emits an {InterfaceImplementerSet} event.
     *
     * Requirements:
     *
     * - the caller must be the current manager for `account`.
     * - `interfaceHash` must not be an {IERC165} interface id (i.e. it must not
     * end in 28 zeroes).
     * - `implementer` must implement {IERC1820Implementer} and return true when
     * queried for support, unless `implementer` is the caller. See
     * {IERC1820Implementer-canImplementInterfaceForAddress}.
     */
    function setInterfaceImplementer(address account, bytes32 _interfaceHash, address implementer) external;

    /**
     * @dev Returns the implementer of `interfaceHash` for `account`. If no such
     * implementer is registered, returns the zero address.
     *
     * If `interfaceHash` is an {IERC165} interface id (i.e. it ends with 28
     * zeroes), `account` will be queried for support of it.
     *
     * `account` being the zero address is an alias for the caller's address.
     */
    function getInterfaceImplementer(address account, bytes32 _interfaceHash) external view returns (address);

    /**
     * @dev Returns the interface hash for an `interfaceName`, as defined in the
     * corresponding
     * https://eips.ethereum.org/EIPS/eip-1820#interface-name[section of the EIP].
     */
    function interfaceHash(string calldata interfaceName) external pure returns (bytes32);

    /**
     *  @notice Updates the cache with whether the contract implements an ERC165 interface or not.
     *  @param account Address of the contract for which to update the cache.
     *  @param interfaceId ERC165 interface for which to update the cache.
     */
    function updateERC165Cache(address account, bytes4 interfaceId) external;

    /**
     *  @notice Checks whether a contract implements an ERC165 interface or not.
     *  If the result is not cached a direct lookup on the contract address is performed.
     *  If the result is not cached or the cached value is out-of-date, the cache MUST be updated manually by calling
     *  {updateERC165Cache} with the contract address.
     *  @param account Address of the contract to check.
     *  @param interfaceId ERC165 interface to check.
     *  @return True if `account` implements `interfaceId`, false otherwise.
     */
    function implementsERC165Interface(address account, bytes4 interfaceId) external view returns (bool);

    /**
     *  @notice Checks whether a contract implements an ERC165 interface or not without using nor updating the cache.
     *  @param account Address of the contract to check.
     *  @param interfaceId ERC165 interface to check.
     *  @return True if `account` implements `interfaceId`, false otherwise.
     */
    function implementsERC165InterfaceNoCache(address account, bytes4 interfaceId) external view returns (bool);

    event InterfaceImplementerSet(address indexed account, bytes32 indexed interfaceHash, address indexed implementer);

    event ManagerChanged(address indexed account, address indexed newManager);
}


// File contracts/token/ERC777/IERC777.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC777Token standard as defined in the EIP.
 *
 * This contract uses the
 * https://eips.ethereum.org/EIPS/eip-1820[ERC1820 registry standard] to let
 * token holders and recipients react to token movements by using setting implementers
 * for the associated interfaces in said registry. See {IERC1820Registry} and
 * {ERC1820Implementer}.
 */
interface IERC777 {
    /**
     * @dev Returns the name of the token.
     */
    function name() external view returns (string memory);

    /**
     * @dev Returns the symbol of the token, usually a shorter version of the
     * name.
     */
    function symbol() external view returns (string memory);

    /**
     * @dev Returns the smallest part of the token that is not divisible. This
     * means all token operations (creation, movement and destruction) must have
     * amounts that are a multiple of this number.
     *
     * For most token contracts, this value will equal 1.
     */
    function granularity() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by an account (`owner`).
     */
    function balanceOf(address owner) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * If send or receive hooks are registered for the caller and `recipient`,
     * the corresponding functions will be called with `data` and empty
     * `operatorData`. See {IERC777Sender} and {IERC777Recipient}.
     *
     * Emits a {Sent} event.
     *
     * Requirements
     *
     * - the caller must have at least `amount` tokens.
     * - `recipient` cannot be the zero address.
     * - if `recipient` is a contract, it must implement the {IERC777Recipient}
     * interface.
     */
    function send(address recipient, uint256 amount, bytes calldata data) external;

    /**
     * @dev Destroys `amount` tokens from the caller's account, reducing the
     * total supply.
     *
     * If a send hook is registered for the caller, the corresponding function
     * will be called with `data` and empty `operatorData`. See {IERC777Sender}.
     *
     * Emits a {Burned} event.
     *
     * Requirements
     *
     * - the caller must have at least `amount` tokens.
     */
    function burn(uint256 amount, bytes calldata data) external;

    /**
     * @dev Returns true if an account is an operator of `tokenHolder`.
     * Operators can send and burn tokens on behalf of their owners. All
     * accounts are their own operator.
     *
     * See {operatorSend} and {operatorBurn}.
     */
    function isOperatorFor(address operator, address tokenHolder) external view returns (bool);

    /**
     * @dev Make an account an operator of the caller.
     *
     * See {isOperatorFor}.
     *
     * Emits an {AuthorizedOperator} event.
     *
     * Requirements
     *
     * - `operator` cannot be calling address.
     */
    function authorizeOperator(address operator) external;

    /**
     * @dev Revoke an account's operator status for the caller.
     *
     * See {isOperatorFor} and {defaultOperators}.
     *
     * Emits a {RevokedOperator} event.
     *
     * Requirements
     *
     * - `operator` cannot be calling address.
     */
    function revokeOperator(address operator) external;

    /**
     * @dev Returns the list of default operators. These accounts are operators
     * for all token holders, even if {authorizeOperator} was never called on
     * them.
     *
     * This list is immutable, but individual holders may revoke these via
     * {revokeOperator}, in which case {isOperatorFor} will return false.
     */
    function defaultOperators() external view returns (address[] memory);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient`. The caller must
     * be an operator of `sender`.
     *
     * If send or receive hooks are registered for `sender` and `recipient`,
     * the corresponding functions will be called with `data` and
     * `operatorData`. See {IERC777Sender} and {IERC777Recipient}.
     *
     * Emits a {Sent} event.
     *
     * Requirements
     *
     * - `sender` cannot be the zero address.
     * - `sender` must have at least `amount` tokens.
     * - the caller must be an operator for `sender`.
     * - `recipient` cannot be the zero address.
     * - if `recipient` is a contract, it must implement the {IERC777Recipient}
     * interface.
     */
    function operatorSend(
        address sender,
        address recipient,
        uint256 amount,
        bytes calldata data,
        bytes calldata operatorData
    ) external;

    /**
     * @dev Destroys `amount` tokens from `account`, reducing the total supply.
     * The caller must be an operator of `account`.
     *
     * If a send hook is registered for `account`, the corresponding function
     * will be called with `data` and `operatorData`. See {IERC777Sender}.
     *
     * Emits a {Burned} event.
     *
     * Requirements
     *
     * - `account` cannot be the zero address.
     * - `account` must have at least `amount` tokens.
     * - the caller must be an operator for `account`.
     */
    function operatorBurn(
        address account,
        uint256 amount,
        bytes calldata data,
        bytes calldata operatorData
    ) external;

    event Sent(
        address indexed operator,
        address indexed from,
        address indexed to,
        uint256 amount,
        bytes data,
        bytes operatorData
    );

    event Minted(address indexed operator, address indexed to, uint256 amount, bytes data, bytes operatorData);

    event Burned(address indexed operator, address indexed from, uint256 amount, bytes data, bytes operatorData);

    event AuthorizedOperator(address indexed operator, address indexed tokenHolder);

    event RevokedOperator(address indexed operator, address indexed tokenHolder);
}


// File contracts/token/ERC777/IERC777Recipient.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC777TokensRecipient standard as defined in the EIP.
 *
 * Accounts can be notified of {IERC777} tokens being sent to them by having a
 * contract implement this interface (contract holders can be their own
 * implementer) and registering it on the
 * https://eips.ethereum.org/EIPS/eip-1820[ERC1820 global registry].
 *
 * See {IERC1820Registry} and {ERC1820Implementer}.
 */
interface IERC777Recipient {
    /**
     * @dev Called by an {IERC777} token contract whenever tokens are being
     * moved or created into a registered account (`to`). The type of operation
     * is conveyed by `from` being the zero address or not.
     *
     * This call occurs _after_ the token contract's state is updated, so
     * {IERC777-balanceOf}, etc., can be used to query the post-operation state.
     *
     * This function may revert to prevent the operation from being executed.
     */
    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}


// File contracts/token/ERC777/IERC777Sender.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Interface of the ERC777TokensSender standard as defined in the EIP.
 *
 * {IERC777} Token holders can be notified of operations performed on their
 * tokens by having a contract implement this interface (contract holders can be
 *  their own implementer) and registering it on the
 * https://eips.ethereum.org/EIPS/eip-1820[ERC1820 global registry].
 *
 * See {IERC1820Registry} and {ERC1820Implementer}.
 */
interface IERC777Sender {
    /**
     * @dev Called by an {IERC777} token contract whenever a registered holder's
     * (`from`) tokens are about to be moved or destroyed. The type of operation
     * is conveyed by `to` being the zero address or not.
     *
     * This call occurs _before_ the token contract's state is updated, so
     * {IERC777-balanceOf}, etc., can be used to query the pre-operation state.
     *
     * This function may revert to prevent the operation from being executed.
     */
    function tokensToSend(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external;
}


// File contracts/token/ERC777/ERC777.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Implementation of the {IERC777} interface.
 *
 * This implementation is agnostic to the way tokens are created. This means
 * that a supply mechanism has to be added in a derived contract using {_mint}.
 *
 * Support for ERC20 is included in this contract, as specified by the EIP: both
 * the ERC777 and ERC20 interfaces can be safely used when interacting with it.
 * Both {IERC777-Sent} and {IERC20-Transfer} events are emitted on token
 * movements.
 *
 * Additionally, the {IERC777-granularity} value is hard-coded to `1`, meaning that there
 * are no special restrictions in the amount of tokens that created, moved, or
 * destroyed. This makes integration with ERC20 applications seamless.
 */
contract ERC777 is Context, IERC777, IERC20 {
    using Address for address;

    IERC1820Registry constant internal _ERC1820_REGISTRY = IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);

    mapping(address => uint256) private _balances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;

    bytes32 private constant _TOKENS_SENDER_INTERFACE_HASH = keccak256("ERC777TokensSender");
    bytes32 private constant _TOKENS_RECIPIENT_INTERFACE_HASH = keccak256("ERC777TokensRecipient");

    // This isn't ever read from - it's only used to respond to the defaultOperators query.
    address[] private _defaultOperatorsArray;

    // Immutable, but accounts may revoke them (tracked in __revokedDefaultOperators).
    mapping(address => bool) private _defaultOperators;

    // For each account, a mapping of its operators and revoked default operators.
    mapping(address => mapping(address => bool)) private _operators;
    mapping(address => mapping(address => bool)) private _revokedDefaultOperators;

    // ERC20-allowances
    mapping (address => mapping (address => uint256)) private _allowances;

    /**
     * @dev `defaultOperators` may be an empty array.
     */
    constructor(
        string memory name_,
        string memory symbol_,
        address[] memory defaultOperators_
    ) {
        _name = name_;
        _symbol = symbol_;

        _defaultOperatorsArray = defaultOperators_;
        for (uint256 i = 0; i < defaultOperators_.length; i++) {
            _defaultOperators[defaultOperators_[i]] = true;
        }

        // register interfaces
        _ERC1820_REGISTRY.setInterfaceImplementer(address(this), keccak256("ERC777Token"), address(this));
        _ERC1820_REGISTRY.setInterfaceImplementer(address(this), keccak256("ERC20Token"), address(this));
    }

    /**
     * @dev See {IERC777-name}.
     */
    function name() public view virtual override returns (string memory) {
        return _name;
    }

    /**
     * @dev See {IERC777-symbol}.
     */
    function symbol() public view virtual override returns (string memory) {
        return _symbol;
    }

    /**
     * @dev See {ERC20-decimals}.
     *
     * Always returns 18, as per the
     * [ERC777 EIP](https://eips.ethereum.org/EIPS/eip-777#backward-compatibility).
     */
    function decimals() public pure virtual returns (uint8) {
        return 18;
    }

    /**
     * @dev See {IERC777-granularity}.
     *
     * This implementation always returns `1`.
     */
    function granularity() public view virtual override returns (uint256) {
        return 1;
    }

    /**
     * @dev See {IERC777-totalSupply}.
     */
    function totalSupply() public view virtual override(IERC20, IERC777) returns (uint256) {
        return _totalSupply;
    }

    /**
     * @dev Returns the amount of tokens owned by an account (`tokenHolder`).
     */
    function balanceOf(address tokenHolder) public view virtual override(IERC20, IERC777) returns (uint256) {
        return _balances[tokenHolder];
    }

    /**
     * @dev See {IERC777-send}.
     *
     * Also emits a {IERC20-Transfer} event for ERC20 compatibility.
     */
    function send(address recipient, uint256 amount, bytes memory data) public virtual override  {
        _send(_msgSender(), recipient, amount, data, "", true);
    }

    /**
     * @dev See {IERC20-transfer}.
     *
     * Unlike `send`, `recipient` is _not_ required to implement the {IERC777Recipient}
     * interface if it is a contract.
     *
     * Also emits a {Sent} event.
     */
    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        require(recipient != address(0), "ERC777: transfer to the zero address");

        address from = _msgSender();

        _callTokensToSend(from, from, recipient, amount, "", "");

        _move(from, from, recipient, amount, "", "");

        _callTokensReceived(from, from, recipient, amount, "", "", false);

        return true;
    }

    /**
     * @dev See {IERC777-burn}.
     *
     * Also emits a {IERC20-Transfer} event for ERC20 compatibility.
     */
    function burn(uint256 amount, bytes memory data) public virtual override  {
        _burn(_msgSender(), amount, data, "");
    }

    /**
     * @dev See {IERC777-isOperatorFor}.
     */
    function isOperatorFor(address operator, address tokenHolder) public view virtual override returns (bool) {
        return operator == tokenHolder ||
            (_defaultOperators[operator] && !_revokedDefaultOperators[tokenHolder][operator]) ||
            _operators[tokenHolder][operator];
    }

    /**
     * @dev See {IERC777-authorizeOperator}.
     */
    function authorizeOperator(address operator) public virtual override  {
        require(_msgSender() != operator, "ERC777: authorizing self as operator");

        if (_defaultOperators[operator]) {
            delete _revokedDefaultOperators[_msgSender()][operator];
        } else {
            _operators[_msgSender()][operator] = true;
        }

        emit AuthorizedOperator(operator, _msgSender());
    }

    /**
     * @dev See {IERC777-revokeOperator}.
     */
    function revokeOperator(address operator) public virtual override  {
        require(operator != _msgSender(), "ERC777: revoking self as operator");

        if (_defaultOperators[operator]) {
            _revokedDefaultOperators[_msgSender()][operator] = true;
        } else {
            delete _operators[_msgSender()][operator];
        }

        emit RevokedOperator(operator, _msgSender());
    }

    /**
     * @dev See {IERC777-defaultOperators}.
     */
    function defaultOperators() public view virtual override returns (address[] memory) {
        return _defaultOperatorsArray;
    }

    /**
     * @dev See {IERC777-operatorSend}.
     *
     * Emits {Sent} and {IERC20-Transfer} events.
     */
    function operatorSend(
        address sender,
        address recipient,
        uint256 amount,
        bytes memory data,
        bytes memory operatorData
    )
        public
        virtual
        override
    {
        require(isOperatorFor(_msgSender(), sender), "ERC777: caller is not an operator for holder");
        _send(sender, recipient, amount, data, operatorData, true);
    }

    /**
     * @dev See {IERC777-operatorBurn}.
     *
     * Emits {Burned} and {IERC20-Transfer} events.
     */
    function operatorBurn(address account, uint256 amount, bytes memory data, bytes memory operatorData) public virtual override {
        require(isOperatorFor(_msgSender(), account), "ERC777: caller is not an operator for holder");
        _burn(account, amount, data, operatorData);
    }

    /**
     * @dev See {IERC20-allowance}.
     *
     * Note that operator and allowance concepts are orthogonal: operators may
     * not have allowance, and accounts with allowance may not be operators
     * themselves.
     */
    function allowance(address holder, address spender) public view virtual override returns (uint256) {
        return _allowances[holder][spender];
    }

    /**
     * @dev See {IERC20-approve}.
     *
     * Note that accounts cannot have allowance issued by their operators.
     */
    function approve(address spender, uint256 value) public virtual override returns (bool) {
        address holder = _msgSender();
        _approve(holder, spender, value);
        return true;
    }

   /**
    * @dev See {IERC20-transferFrom}.
    *
    * Note that operator and allowance concepts are orthogonal: operators cannot
    * call `transferFrom` (unless they have allowance), and accounts with
    * allowance cannot call `operatorSend` (unless they are operators).
    *
    * Emits {Sent}, {IERC20-Transfer} and {IERC20-Approval} events.
    */
    function transferFrom(address holder, address recipient, uint256 amount) public virtual override returns (bool) {
        require(recipient != address(0), "ERC777: transfer to the zero address");
        require(holder != address(0), "ERC777: transfer from the zero address");

        address spender = _msgSender();

        _callTokensToSend(spender, holder, recipient, amount, "", "");

        _move(spender, holder, recipient, amount, "", "");

        uint256 currentAllowance = _allowances[holder][spender];
        require(currentAllowance >= amount, "ERC777: transfer amount exceeds allowance");
        _approve(holder, spender, currentAllowance - amount);

        _callTokensReceived(spender, holder, recipient, amount, "", "", false);

        return true;
    }

    /**
     * @dev Creates `amount` tokens and assigns them to `account`, increasing
     * the total supply.
     *
     * If a send hook is registered for `account`, the corresponding function
     * will be called with `operator`, `data` and `operatorData`.
     *
     * See {IERC777Sender} and {IERC777Recipient}.
     *
     * Emits {Minted} and {IERC20-Transfer} events.
     *
     * Requirements
     *
     * - `account` cannot be the zero address.
     * - if `account` is a contract, it must implement the {IERC777Recipient}
     * interface.
     */
    function _mint(
        address account,
        uint256 amount,
        bytes memory userData,
        bytes memory operatorData
    )
        internal
        virtual
    {
        require(account != address(0), "ERC777: mint to the zero address");

        address operator = _msgSender();

        _beforeTokenTransfer(operator, address(0), account, amount);

        // Update state variables
        _totalSupply += amount;
        _balances[account] += amount;

        _callTokensReceived(operator, address(0), account, amount, userData, operatorData, true);

        emit Minted(operator, account, amount, userData, operatorData);
        emit Transfer(address(0), account, amount);
    }

    /**
     * @dev Send tokens
     * @param from address token holder address
     * @param to address recipient address
     * @param amount uint256 amount of tokens to transfer
     * @param userData bytes extra information provided by the token holder (if any)
     * @param operatorData bytes extra information provided by the operator (if any)
     * @param requireReceptionAck if true, contract recipients are required to implement ERC777TokensRecipient
     */
    function _send(
        address from,
        address to,
        uint256 amount,
        bytes memory userData,
        bytes memory operatorData,
        bool requireReceptionAck
    )
        internal
        virtual
    {
        require(from != address(0), "ERC777: send from the zero address");
        require(to != address(0), "ERC777: send to the zero address");

        address operator = _msgSender();

        _callTokensToSend(operator, from, to, amount, userData, operatorData);

        _move(operator, from, to, amount, userData, operatorData);

        _callTokensReceived(operator, from, to, amount, userData, operatorData, requireReceptionAck);
    }

    /**
     * @dev Burn tokens
     * @param from address token holder address
     * @param amount uint256 amount of tokens to burn
     * @param data bytes extra information provided by the token holder
     * @param operatorData bytes extra information provided by the operator (if any)
     */
    function _burn(
        address from,
        uint256 amount,
        bytes memory data,
        bytes memory operatorData
    )
        internal
        virtual
    {
        require(from != address(0), "ERC777: burn from the zero address");

        address operator = _msgSender();

        _callTokensToSend(operator, from, address(0), amount, data, operatorData);

        _beforeTokenTransfer(operator, from, address(0), amount);

        // Update state variables
        uint256 fromBalance = _balances[from];
        require(fromBalance >= amount, "ERC777: burn amount exceeds balance");
        _balances[from] = fromBalance - amount;
        _totalSupply -= amount;

        emit Burned(operator, from, amount, data, operatorData);
        emit Transfer(from, address(0), amount);
    }

    function _move(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes memory userData,
        bytes memory operatorData
    )
        private
    {
        _beforeTokenTransfer(operator, from, to, amount);

        uint256 fromBalance = _balances[from];
        require(fromBalance >= amount, "ERC777: transfer amount exceeds balance");
        _balances[from] = fromBalance - amount;
        _balances[to] += amount;

        emit Sent(operator, from, to, amount, userData, operatorData);
        emit Transfer(from, to, amount);
    }

    /**
     * @dev See {ERC20-_approve}.
     *
     * Note that accounts cannot have allowance issued by their operators.
     */
    function _approve(address holder, address spender, uint256 value) internal {
        require(holder != address(0), "ERC777: approve from the zero address");
        require(spender != address(0), "ERC777: approve to the zero address");

        _allowances[holder][spender] = value;
        emit Approval(holder, spender, value);
    }

    /**
     * @dev Call from.tokensToSend() if the interface is registered
     * @param operator address operator requesting the transfer
     * @param from address token holder address
     * @param to address recipient address
     * @param amount uint256 amount of tokens to transfer
     * @param userData bytes extra information provided by the token holder (if any)
     * @param operatorData bytes extra information provided by the operator (if any)
     */
    function _callTokensToSend(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes memory userData,
        bytes memory operatorData
    )
        private
    {
        address implementer = _ERC1820_REGISTRY.getInterfaceImplementer(from, _TOKENS_SENDER_INTERFACE_HASH);
        if (implementer != address(0)) {
            IERC777Sender(implementer).tokensToSend(operator, from, to, amount, userData, operatorData);
        }
    }

    /**
     * @dev Call to.tokensReceived() if the interface is registered. Reverts if the recipient is a contract but
     * tokensReceived() was not registered for the recipient
     * @param operator address operator requesting the transfer
     * @param from address token holder address
     * @param to address recipient address
     * @param amount uint256 amount of tokens to transfer
     * @param userData bytes extra information provided by the token holder (if any)
     * @param operatorData bytes extra information provided by the operator (if any)
     * @param requireReceptionAck if true, contract recipients are required to implement ERC777TokensRecipient
     */
    function _callTokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes memory userData,
        bytes memory operatorData,
        bool requireReceptionAck
    )
        private
    {
        address implementer = _ERC1820_REGISTRY.getInterfaceImplementer(to, _TOKENS_RECIPIENT_INTERFACE_HASH);
        if (implementer != address(0)) {
            IERC777Recipient(implementer).tokensReceived(operator, from, to, amount, userData, operatorData);
        } else if (requireReceptionAck) {
            require(!to.isContract(), "ERC777: token recipient contract has no implementer for ERC777TokensRecipient");
        }
    }

    /**
     * @dev Hook that is called before any token transfer. This includes
     * calls to {send}, {transfer}, {operatorSend}, minting and burning.
     *
     * Calling conditions:
     *
     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens
     * will be to transferred to `to`.
     * - when `from` is zero, `amount` tokens will be minted for `to`.
     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(address operator, address from, address to, uint256 amount) internal virtual { }
}


// File contracts/mocks/ERC777Mock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC777Mock is Context, ERC777 {
    event BeforeTokenTransfer();

    constructor(
        address initialHolder,
        uint256 initialBalance,
        string memory name,
        string memory symbol,
        address[] memory defaultOperators
    ) ERC777(name, symbol, defaultOperators) {
        _mint(initialHolder, initialBalance, "", "");
    }

    function mintInternal (
        address to,
        uint256 amount,
        bytes memory userData,
        bytes memory operatorData
    ) public {
        _mint(to, amount, userData, operatorData);
    }

    function approveInternal(address holder, address spender, uint256 value) public {
        _approve(holder, spender, value);
    }

    function _beforeTokenTransfer(address, address, address, uint256) internal override {
        emit BeforeTokenTransfer();
    }
}


// File contracts/mocks/ERC777SenderRecipientMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC777SenderRecipientMock is Context, IERC777Sender, IERC777Recipient, ERC1820Implementer {
    event TokensToSendCalled(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes data,
        bytes operatorData,
        address token,
        uint256 fromBalance,
        uint256 toBalance
    );

    event TokensReceivedCalled(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes data,
        bytes operatorData,
        address token,
        uint256 fromBalance,
        uint256 toBalance
    );

    // Emitted in ERC777Mock. Here for easier decoding
    event BeforeTokenTransfer();

    bool private _shouldRevertSend;
    bool private _shouldRevertReceive;

    IERC1820Registry private _erc1820 = IERC1820Registry(0x1820a4B7618BdE71Dce8cdc73aAB6C95905faD24);

    bytes32 constant private _TOKENS_SENDER_INTERFACE_HASH = keccak256("ERC777TokensSender");
    bytes32 constant private _TOKENS_RECIPIENT_INTERFACE_HASH = keccak256("ERC777TokensRecipient");

    function tokensToSend(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external override {
        if (_shouldRevertSend) {
            revert();
        }

        IERC777 token = IERC777(_msgSender());

        uint256 fromBalance = token.balanceOf(from);
        // when called due to burn, to will be the zero address, which will have a balance of 0
        uint256 toBalance = token.balanceOf(to);

        emit TokensToSendCalled(
            operator,
            from,
            to,
            amount,
            userData,
            operatorData,
            address(token),
            fromBalance,
            toBalance
        );
    }

    function tokensReceived(
        address operator,
        address from,
        address to,
        uint256 amount,
        bytes calldata userData,
        bytes calldata operatorData
    ) external override {
        if (_shouldRevertReceive) {
            revert();
        }

        IERC777 token = IERC777(_msgSender());

        uint256 fromBalance = token.balanceOf(from);
        // when called due to burn, to will be the zero address, which will have a balance of 0
        uint256 toBalance = token.balanceOf(to);

        emit TokensReceivedCalled(
            operator,
            from,
            to,
            amount,
            userData,
            operatorData,
            address(token),
            fromBalance,
            toBalance
        );
    }

    function senderFor(address account) public {
        _registerInterfaceForAddress(_TOKENS_SENDER_INTERFACE_HASH, account);

        address self = address(this);
        if (account == self) {
            registerSender(self);
        }
    }

    function registerSender(address sender) public {
        _erc1820.setInterfaceImplementer(address(this), _TOKENS_SENDER_INTERFACE_HASH, sender);
    }

    function recipientFor(address account) public {
        _registerInterfaceForAddress(_TOKENS_RECIPIENT_INTERFACE_HASH, account);

        address self = address(this);
        if (account == self) {
            registerRecipient(self);
        }
    }

    function registerRecipient(address recipient) public {
        _erc1820.setInterfaceImplementer(address(this), _TOKENS_RECIPIENT_INTERFACE_HASH, recipient);
    }

    function setShouldRevertSend(bool shouldRevert) public {
        _shouldRevertSend = shouldRevert;
    }

    function setShouldRevertReceive(bool shouldRevert) public {
        _shouldRevertReceive = shouldRevert;
    }

    function send(IERC777 token, address to, uint256 amount, bytes memory data) public {
        // This is 777's send function, not the Solidity send function
        token.send(to, amount, data); // solhint-disable-line check-send-result
    }

    function burn(IERC777 token, uint256 amount, bytes memory data) public {
        token.burn(amount, data);
    }
}


// File contracts/utils/Initializable.sol

// SPDX-License-Identifier: MIT

// solhint-disable-next-line compiler-version
pragma solidity ^0.8.0;
/**
 * @dev This is a base contract to aid in writing upgradeable contracts, or any kind of contract that will be deployed
 * behind a proxy. Since a proxied contract can't have a constructor, it's common to move constructor logic to an
 * external initializer function, usually called `initialize`. It then becomes necessary to protect this initializer
 * function so it can only be called once. The {initializer} modifier provided by this contract will have this effect.
 *
 * TIP: To avoid leaving the proxy in an uninitialized state, the initializer function should be called as early as
 * possible by providing the encoded function call as the `_data` argument to {UpgradeableProxy-constructor}.
 *
 * CAUTION: When used with inheritance, manual care must be taken to not invoke a parent initializer twice, or to ensure
 * that all initializers are idempotent. This is not verified automatically as constructors are by Solidity.
 */
abstract contract Initializable {

    /**
     * @dev Indicates that the contract has been initialized.
     */
    bool private _initialized;

    /**
     * @dev Indicates that the contract is in the process of being initialized.
     */
    bool private _initializing;

    /**
     * @dev Modifier to protect an initializer function from being invoked twice.
     */
    modifier initializer() {
        require(_initializing || !_initialized, "Initializable: contract is already initialized");

        bool isTopLevelCall = !_initializing;
        if (isTopLevelCall) {
            _initializing = true;
            _initialized = true;
        }

        _;

        if (isTopLevelCall) {
            _initializing = false;
        }
    }
}


// File contracts/mocks/InitializableMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title InitializableMock
 * @dev This contract is a mock to test initializable functionality
 */
contract InitializableMock is Initializable {

  bool public initializerRan;
  uint256 public x;

  function initialize() public initializer {
    initializerRan = true;
  }

  function initializeNested() public initializer {
    initialize();
  }

  function initializeWithX(uint256 _x) public payable initializer {
    x = _x;
  }

  function nonInitializable(uint256 _x) public payable {
    x = _x;
  }

  function fail() public pure {
    require(false, "InitializableMock forced failure");
  }

}


// File contracts/mocks/MathMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract MathMock {
    function max(uint256 a, uint256 b) public pure returns (uint256) {
        return Math.max(a, b);
    }

    function min(uint256 a, uint256 b) public pure returns (uint256) {
        return Math.min(a, b);
    }

    function average(uint256 a, uint256 b) public pure returns (uint256) {
        return Math.average(a, b);
    }
}


// File contracts/utils/cryptography/MerkleProof.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev These functions deal with verification of Merkle trees (hash trees),
 */
library MerkleProof {
    /**
     * @dev Returns true if a `leaf` can be proved to be a part of a Merkle tree
     * defined by `root`. For this, a `proof` must be provided, containing
     * sibling hashes on the branch from the leaf to the root of the tree. Each
     * pair of leaves and each pair of pre-images are assumed to be sorted.
     */
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }

        // Check if the computed hash (root) is equal to the provided root
        return computedHash == root;
    }
}


// File contracts/mocks/MerkleProofWrapper.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract MerkleProofWrapper {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) public pure returns (bool) {
        return MerkleProof.verify(proof, root, leaf);
    }
}


// File contracts/mocks/MultipleInheritanceInitializableMocks.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
// Sample contracts showing upgradeability with multiple inheritance.
// Child contract inherits from Father and Mother contracts, and Father extends from Gramps.
//
//         Human
//       /       \
//      |       Gramps
//      |         |
//    Mother    Father
//      |         |
//      -- Child --

/**
 * Sample base intializable contract that is a human
 */
contract SampleHuman is Initializable {
  bool public isHuman;

  function initialize() public initializer {
    isHuman = true;
  }
}

/**
 * Sample base intializable contract that defines a field mother
 */
contract SampleMother is Initializable, SampleHuman {
  uint256 public mother;

  function initialize(uint256 value) public initializer virtual {
    SampleHuman.initialize();
    mother = value;
  }
}

/**
 * Sample base intializable contract that defines a field gramps
 */
contract SampleGramps is Initializable, SampleHuman {
  string public gramps;

  function initialize(string memory value) public initializer virtual {
    SampleHuman.initialize();
    gramps = value;
  }
}

/**
 * Sample base intializable contract that defines a field father and extends from gramps
 */
contract SampleFather is Initializable, SampleGramps {
  uint256 public father;

  function initialize(string memory _gramps, uint256 _father) public initializer {
    SampleGramps.initialize(_gramps);
    father = _father;
  }
}

/**
 * Child extends from mother, father (gramps)
 */
contract SampleChild is Initializable, SampleMother, SampleFather {
  uint256 public child;

  function initialize(uint256 _mother, string memory _gramps, uint256 _father, uint256 _child) public initializer {
    SampleMother.initialize(_mother);
    SampleFather.initialize(_gramps, _father);
    child = _child;
  }
}


// File contracts/mocks/OwnableMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract OwnableMock is Ownable { }


// File contracts/mocks/PausableMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract PausableMock is Pausable {
    bool public drasticMeasureTaken;
    uint256 public count;

    constructor () {
        drasticMeasureTaken = false;
        count = 0;
    }

    function normalProcess() external whenNotPaused {
        count++;
    }

    function drasticMeasure() external whenPaused {
        drasticMeasureTaken = true;
    }

    function pause() external {
        _pause();
    }

    function unpause() external {
        _unpause();
    }
}


// File contracts/security/PullPayment.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Simple implementation of a
 * https://consensys.github.io/smart-contract-best-practices/recommendations/#favor-pull-over-push-for-external-calls[pull-payment]
 * strategy, where the paying contract doesn't interact directly with the
 * receiver account, which must withdraw its payments itself.
 *
 * Pull-payments are often considered the best practice when it comes to sending
 * Ether, security-wise. It prevents recipients from blocking execution, and
 * eliminates reentrancy concerns.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 *
 * To use, derive from the `PullPayment` contract, and use {_asyncTransfer}
 * instead of Solidity's `transfer` function. Payees can query their due
 * payments with {payments}, and retrieve them with {withdrawPayments}.
 */
abstract contract PullPayment {
    Escrow immutable private _escrow;

    constructor () {
        _escrow = new Escrow();
    }

    /**
     * @dev Withdraw accumulated payments, forwarding all gas to the recipient.
     *
     * Note that _any_ account can call this function, not just the `payee`.
     * This means that contracts unaware of the `PullPayment` protocol can still
     * receive funds this way, by having a separate account call
     * {withdrawPayments}.
     *
     * WARNING: Forwarding all gas opens the door to reentrancy vulnerabilities.
     * Make sure you trust the recipient, or are either following the
     * checks-effects-interactions pattern or using {ReentrancyGuard}.
     *
     * @param payee Whose payments will be withdrawn.
     */
    function withdrawPayments(address payable payee) public virtual {
        _escrow.withdraw(payee);
    }

    /**
     * @dev Returns the payments owed to an address.
     * @param dest The creditor's address.
     */
    function payments(address dest) public view returns (uint256) {
        return _escrow.depositsOf(dest);
    }

    /**
     * @dev Called by the payer to store the sent amount as credit to be pulled.
     * Funds sent in this way are stored in an intermediate {Escrow} contract, so
     * there is no danger of them being spent before withdrawal.
     *
     * @param dest The destination address of the funds.
     * @param amount The amount to transfer.
     */
    function _asyncTransfer(address dest, uint256 amount) internal virtual {
        _escrow.deposit{ value: amount }(dest);
    }
}


// File contracts/mocks/PullPaymentMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
// mock class using PullPayment
contract PullPaymentMock is PullPayment {
    constructor () payable { }

    // test helper function to call asyncTransfer
    function callTransfer(address dest, uint256 amount) public {
        _asyncTransfer(dest, amount);
    }
}


// File contracts/mocks/ReentrancyAttack.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ReentrancyAttack is Context {
    function callSender(bytes4 data) public {
        // solhint-disable-next-line avoid-low-level-calls
        (bool success,) = _msgSender().call(abi.encodeWithSelector(data));
        require(success, "ReentrancyAttack: failed call");
    }
}


// File contracts/security/ReentrancyGuard.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Contract module that helps prevent reentrant calls to a function.
 *
 * Inheriting from `ReentrancyGuard` will make the {nonReentrant} modifier
 * available, which can be applied to functions to make sure there are no nested
 * (reentrant) calls to them.
 *
 * Note that because there is a single `nonReentrant` guard, functions marked as
 * `nonReentrant` may not call one another. This can be worked around by making
 * those functions `private`, and then adding `external` `nonReentrant` entry
 * points to them.
 *
 * TIP: If you would like to learn more about reentrancy and alternative ways
 * to protect against it, check out our blog post
 * https://blog.openzeppelin.com/reentrancy-after-istanbul/[Reentrancy After Istanbul].
 */
abstract contract ReentrancyGuard {
    // Booleans are more expensive than uint256 or any type that takes up a full
    // word because each write operation emits an extra SLOAD to first read the
    // slot's contents, replace the bits taken up by the boolean, and then write
    // back. This is the compiler's defense against contract upgrades and
    // pointer aliasing, and it cannot be disabled.

    // The values being non-zero value makes deployment a bit more expensive,
    // but in exchange the refund on every call to nonReentrant will be lower in
    // amount. Since refunds are capped to a percentage of the total
    // transaction's gas, it is best to keep them low in cases like this one, to
    // increase the likelihood of the full refund coming into effect.
    uint256 private constant _NOT_ENTERED = 1;
    uint256 private constant _ENTERED = 2;

    uint256 private _status;

    constructor () {
        _status = _NOT_ENTERED;
    }

    /**
     * @dev Prevents a contract from calling itself, directly or indirectly.
     * Calling a `nonReentrant` function from another `nonReentrant`
     * function is not supported. It is possible to prevent this from happening
     * by making the `nonReentrant` function external, and make it call a
     * `private` function that does the actual work.
     */
    modifier nonReentrant() {
        // On the first call to nonReentrant, _notEntered will be true
        require(_status != _ENTERED, "ReentrancyGuard: reentrant call");

        // Any calls to nonReentrant after this point will fail
        _status = _ENTERED;

        _;

        // By storing the original value once again, a refund is triggered (see
        // https://eips.ethereum.org/EIPS/eip-2200)
        _status = _NOT_ENTERED;
    }
}


// File contracts/mocks/ReentrancyMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ReentrancyMock is ReentrancyGuard {
    uint256 public counter;

    constructor () {
        counter = 0;
    }

    function callback() external nonReentrant {
        _count();
    }

    function countLocalRecursive(uint256 n) public nonReentrant {
        if (n > 0) {
            _count();
            countLocalRecursive(n - 1);
        }
    }

    function countThisRecursive(uint256 n) public nonReentrant {
        if (n > 0) {
            _count();
            // solhint-disable-next-line avoid-low-level-calls
            (bool success,) = address(this).call(abi.encodeWithSignature("countThisRecursive(uint256)", n - 1));
            require(success, "ReentrancyMock: failed call");
        }
    }

    function countAndCall(ReentrancyAttack attacker) public nonReentrant {
        _count();
        bytes4 func = bytes4(keccak256("callback()"));
        attacker.callSender(func);
    }

    function _count() private {
        counter += 1;
    }
}


// File contracts/mocks/RegressionImplementation.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Implementation1 is Initializable {
  uint internal _value;

  function initialize() public initializer {
  }

  function setValue(uint _number) public {
    _value = _number;
  }
}

contract Implementation2 is Initializable {
  uint internal _value;

  function initialize() public initializer {
  }

  function setValue(uint _number) public {
    _value = _number;
  }

  function getValue() public view returns (uint) {
    return _value;
  }
}

contract Implementation3 is Initializable {
  uint internal _value;

  function initialize() public initializer {
  }

  function setValue(uint _number) public {
    _value = _number;
  }

  function getValue(uint _number) public view returns (uint) {
    return _value + _number;
  }
}

contract Implementation4 is Initializable {
  uint internal _value;

  function initialize() public initializer {
  }

  function setValue(uint _number) public {
    _value = _number;
  }

  function getValue() public view returns (uint) {
    return _value;
  }

  // solhint-disable-next-line payable-fallback
  fallback() external {
    _value = 1;
  }
}


// File contracts/utils/math/SafeCast.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Wrappers over Solidity's uintXX/intXX casting operators with added overflow
 * checks.
 *
 * Downcasting from uint256/int256 in Solidity does not revert on overflow. This can
 * easily result in undesired exploitation or bugs, since developers usually
 * assume that overflows raise errors. `SafeCast` restores this intuition by
 * reverting the transaction when such an operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 *
 * Can be combined with {SafeMath} and {SignedSafeMath} to extend it to smaller types, by performing
 * all math on `uint256` and `int256` and then downcasting.
 */
library SafeCast {
    /**
     * @dev Returns the downcasted uint128 from uint256, reverting on
     * overflow (when the input is greater than largest uint128).
     *
     * Counterpart to Solidity's `uint128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     */
    function toUint128(uint256 value) internal pure returns (uint128) {
        require(value < 2**128, "SafeCast: value doesn\'t fit in 128 bits");
        return uint128(value);
    }

    /**
     * @dev Returns the downcasted uint64 from uint256, reverting on
     * overflow (when the input is greater than largest uint64).
     *
     * Counterpart to Solidity's `uint64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     */
    function toUint64(uint256 value) internal pure returns (uint64) {
        require(value < 2**64, "SafeCast: value doesn\'t fit in 64 bits");
        return uint64(value);
    }

    /**
     * @dev Returns the downcasted uint32 from uint256, reverting on
     * overflow (when the input is greater than largest uint32).
     *
     * Counterpart to Solidity's `uint32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     */
    function toUint32(uint256 value) internal pure returns (uint32) {
        require(value < 2**32, "SafeCast: value doesn\'t fit in 32 bits");
        return uint32(value);
    }

    /**
     * @dev Returns the downcasted uint16 from uint256, reverting on
     * overflow (when the input is greater than largest uint16).
     *
     * Counterpart to Solidity's `uint16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     */
    function toUint16(uint256 value) internal pure returns (uint16) {
        require(value < 2**16, "SafeCast: value doesn\'t fit in 16 bits");
        return uint16(value);
    }

    /**
     * @dev Returns the downcasted uint8 from uint256, reverting on
     * overflow (when the input is greater than largest uint8).
     *
     * Counterpart to Solidity's `uint8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits.
     */
    function toUint8(uint256 value) internal pure returns (uint8) {
        require(value < 2**8, "SafeCast: value doesn\'t fit in 8 bits");
        return uint8(value);
    }

    /**
     * @dev Converts a signed int256 into an unsigned uint256.
     *
     * Requirements:
     *
     * - input must be greater than or equal to 0.
     */
    function toUint256(int256 value) internal pure returns (uint256) {
        require(value >= 0, "SafeCast: value must be positive");
        return uint256(value);
    }

    /**
     * @dev Returns the downcasted int128 from int256, reverting on
     * overflow (when the input is less than smallest int128 or
     * greater than largest int128).
     *
     * Counterpart to Solidity's `int128` operator.
     *
     * Requirements:
     *
     * - input must fit into 128 bits
     *
     * _Available since v3.1._
     */
    function toInt128(int256 value) internal pure returns (int128) {
        require(value >= -2**127 && value < 2**127, "SafeCast: value doesn\'t fit in 128 bits");
        return int128(value);
    }

    /**
     * @dev Returns the downcasted int64 from int256, reverting on
     * overflow (when the input is less than smallest int64 or
     * greater than largest int64).
     *
     * Counterpart to Solidity's `int64` operator.
     *
     * Requirements:
     *
     * - input must fit into 64 bits
     *
     * _Available since v3.1._
     */
    function toInt64(int256 value) internal pure returns (int64) {
        require(value >= -2**63 && value < 2**63, "SafeCast: value doesn\'t fit in 64 bits");
        return int64(value);
    }

    /**
     * @dev Returns the downcasted int32 from int256, reverting on
     * overflow (when the input is less than smallest int32 or
     * greater than largest int32).
     *
     * Counterpart to Solidity's `int32` operator.
     *
     * Requirements:
     *
     * - input must fit into 32 bits
     *
     * _Available since v3.1._
     */
    function toInt32(int256 value) internal pure returns (int32) {
        require(value >= -2**31 && value < 2**31, "SafeCast: value doesn\'t fit in 32 bits");
        return int32(value);
    }

    /**
     * @dev Returns the downcasted int16 from int256, reverting on
     * overflow (when the input is less than smallest int16 or
     * greater than largest int16).
     *
     * Counterpart to Solidity's `int16` operator.
     *
     * Requirements:
     *
     * - input must fit into 16 bits
     *
     * _Available since v3.1._
     */
    function toInt16(int256 value) internal pure returns (int16) {
        require(value >= -2**15 && value < 2**15, "SafeCast: value doesn\'t fit in 16 bits");
        return int16(value);
    }

    /**
     * @dev Returns the downcasted int8 from int256, reverting on
     * overflow (when the input is less than smallest int8 or
     * greater than largest int8).
     *
     * Counterpart to Solidity's `int8` operator.
     *
     * Requirements:
     *
     * - input must fit into 8 bits.
     *
     * _Available since v3.1._
     */
    function toInt8(int256 value) internal pure returns (int8) {
        require(value >= -2**7 && value < 2**7, "SafeCast: value doesn\'t fit in 8 bits");
        return int8(value);
    }

    /**
     * @dev Converts an unsigned uint256 into a signed int256.
     *
     * Requirements:
     *
     * - input must be less than or equal to maxInt256.
     */
    function toInt256(uint256 value) internal pure returns (int256) {
        require(value < 2**255, "SafeCast: value doesn't fit in an int256");
        return int256(value);
    }
}


// File contracts/mocks/SafeCastMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract SafeCastMock {
    using SafeCast for uint;
    using SafeCast for int;

    function toUint256(int a) public pure returns (uint256) {
        return a.toUint256();
    }

    function toInt256(uint a) public pure returns (int256) {
        return a.toInt256();
    }

    function toUint128(uint a) public pure returns (uint128) {
        return a.toUint128();
    }

    function toUint64(uint a) public pure returns (uint64) {
        return a.toUint64();
    }

    function toUint32(uint a) public pure returns (uint32) {
        return a.toUint32();
    }

    function toUint16(uint a) public pure returns (uint16) {
        return a.toUint16();
    }

    function toUint8(uint a) public pure returns (uint8) {
        return a.toUint8();
    }

    function toInt128(int a) public pure returns (int128) {
        return a.toInt128();
    }

    function toInt64(int a) public pure returns (int64) {
        return a.toInt64();
    }

    function toInt32(int a) public pure returns (int32) {
        return a.toInt32();
    }

    function toInt16(int a) public pure returns (int16) {
        return a.toInt16();
    }

    function toInt8(int a) public pure returns (int8) {
        return a.toInt8();
    }
}


// File contracts/token/ERC20/utils/SafeERC20.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title SafeERC20
 * @dev Wrappers around ERC20 operations that throw on failure (when the token
 * contract returns false). Tokens that return no value (and instead revert or
 * throw on failure) are also supported, non-reverting calls are assumed to be
 * successful.
 * To use this library you can add a `using SafeERC20 for IERC20;` statement to your contract,
 * which allows you to call the safe operations as `token.safeTransfer(...)`, etc.
 */
library SafeERC20 {
    using Address for address;

    function safeTransfer(IERC20 token, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transfer.selector, to, value));
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 value) internal {
        _callOptionalReturn(token, abi.encodeWithSelector(token.transferFrom.selector, from, to, value));
    }

    /**
     * @dev Deprecated. This function has issues similar to the ones found in
     * {IERC20-approve}, and its usage is discouraged.
     *
     * Whenever possible, use {safeIncreaseAllowance} and
     * {safeDecreaseAllowance} instead.
     */
    function safeApprove(IERC20 token, address spender, uint256 value) internal {
        // safeApprove should only be called when setting an initial allowance,
        // or when resetting it to zero. To increase and decrease it, use
        // 'safeIncreaseAllowance' and 'safeDecreaseAllowance'
        // solhint-disable-next-line max-line-length
        require((value == 0) || (token.allowance(address(this), spender) == 0),
            "SafeERC20: approve from non-zero to non-zero allowance"
        );
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, value));
    }

    function safeIncreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        uint256 newAllowance = token.allowance(address(this), spender) + value;
        _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
    }

    function safeDecreaseAllowance(IERC20 token, address spender, uint256 value) internal {
        unchecked {
            uint256 oldAllowance = token.allowance(address(this), spender);
            require(oldAllowance >= value, "SafeERC20: decreased allowance below zero");
            uint256 newAllowance = oldAllowance - value;
            _callOptionalReturn(token, abi.encodeWithSelector(token.approve.selector, spender, newAllowance));
        }
    }

    /**
     * @dev Imitates a Solidity high-level call (i.e. a regular function call to a contract), relaxing the requirement
     * on the return value: the return value is optional (but if data is returned, it must not be false).
     * @param token The token targeted by the call.
     * @param data The call data (encoded using abi.encode or one of its variants).
     */
    function _callOptionalReturn(IERC20 token, bytes memory data) private {
        // We need to perform a low level call here, to bypass Solidity's return data size checking mechanism, since
        // we're implementing it ourselves. We use {Address.functionCall} to perform this call, which verifies that
        // the target address contains contract code and also asserts for success in the low-level call.

        bytes memory returndata = address(token).functionCall(data, "SafeERC20: low-level call failed");
        if (returndata.length > 0) { // Return data is optional
            // solhint-disable-next-line max-line-length
            require(abi.decode(returndata, (bool)), "SafeERC20: ERC20 operation did not succeed");
        }
    }
}


// File contracts/mocks/SafeERC20Helper.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract ERC20ReturnFalseMock is Context {
    uint256 private _allowance;

    // IERC20's functions are not pure, but these mock implementations are: to prevent Solidity from issuing warnings,
    // we write to a dummy state variable.
    uint256 private _dummy;

    function transfer(address, uint256) public returns (bool) {
        _dummy = 0;
        return false;
    }

    function transferFrom(address, address, uint256) public returns (bool) {
        _dummy = 0;
        return false;
    }

    function approve(address, uint256) public returns (bool) {
        _dummy = 0;
        return false;
    }

    function allowance(address, address) public view returns (uint256) {
        require(_dummy == 0); // Duummy read from a state variable so that the function is view
        return 0;
    }
}

contract ERC20ReturnTrueMock is Context {
    mapping (address => uint256) private _allowances;

    // IERC20's functions are not pure, but these mock implementations are: to prevent Solidity from issuing warnings,
    // we write to a dummy state variable.
    uint256 private _dummy;

    function transfer(address, uint256) public returns (bool) {
        _dummy = 0;
        return true;
    }

    function transferFrom(address, address, uint256) public returns (bool) {
        _dummy = 0;
        return true;
    }

    function approve(address, uint256) public returns (bool) {
        _dummy = 0;
        return true;
    }

    function setAllowance(uint256 allowance_) public {
        _allowances[_msgSender()] = allowance_;
    }

    function allowance(address owner, address) public view returns (uint256) {
        return _allowances[owner];
    }
}

contract ERC20NoReturnMock is Context {
    mapping (address => uint256) private _allowances;

    // IERC20's functions are not pure, but these mock implementations are: to prevent Solidity from issuing warnings,
    // we write to a dummy state variable.
    uint256 private _dummy;

    function transfer(address, uint256) public {
        _dummy = 0;
    }

    function transferFrom(address, address, uint256) public {
        _dummy = 0;
    }

    function approve(address, uint256) public {
        _dummy = 0;
    }

    function setAllowance(uint256 allowance_) public {
        _allowances[_msgSender()] = allowance_;
    }

    function allowance(address owner, address) public view returns (uint256) {
        return _allowances[owner];
    }
}

contract SafeERC20Wrapper is Context {
    using SafeERC20 for IERC20;

    IERC20 private _token;

    constructor (IERC20 token) {
        _token = token;
    }

    function transfer() public {
        _token.safeTransfer(address(0), 0);
    }

    function transferFrom() public {
        _token.safeTransferFrom(address(0), address(0), 0);
    }

    function approve(uint256 amount) public {
        _token.safeApprove(address(0), amount);
    }

    function increaseAllowance(uint256 amount) public {
        _token.safeIncreaseAllowance(address(0), amount);
    }

    function decreaseAllowance(uint256 amount) public {
        _token.safeDecreaseAllowance(address(0), amount);
    }

    function setAllowance(uint256 allowance_) public {
        ERC20ReturnTrueMock(address(_token)).setAllowance(allowance_);
    }

    function allowance() public view returns (uint256) {
        return _token.allowance(address(0), address(0));
    }
}


// File contracts/utils/math/SafeMath.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

// CAUTION
// This version of SafeMath should only be used with Solidity 0.8 or later,
// because it relies on the compiler's built in overflow checks.

/**
 * @dev Wrappers over Solidity's arithmetic operations.
 *
 * NOTE: `SafeMath` is no longer needed starting with Solidity 0.8. The compiler
 * now has built in overflow checking.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryAdd(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            uint256 c = a + b;
            if (c < a) return (false, 0);
            return (true, c);
        }
    }

    /**
     * @dev Returns the substraction of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function trySub(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b > a) return (false, 0);
            return (true, a - b);
        }
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, with an overflow flag.
     *
     * _Available since v3.4._
     */
    function tryMul(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
            // benefit is lost if 'b' is also tested.
            // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
            if (a == 0) return (true, 0);
            uint256 c = a * b;
            if (c / a != b) return (false, 0);
            return (true, c);
        }
    }

    /**
     * @dev Returns the division of two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryDiv(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a / b);
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers, with a division by zero flag.
     *
     * _Available since v3.4._
     */
    function tryMod(uint256 a, uint256 b) internal pure returns (bool, uint256) {
        unchecked {
            if (b == 0) return (false, 0);
            return (true, a % b);
        }
    }

    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     *
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        return a + b;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return a - b;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     *
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        return a * b;
    }

    /**
     * @dev Returns the integer division of two unsigned integers, reverting on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator.
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return a / b;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * reverting when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return a % b;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {trySub}.
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        unchecked {
            require(b <= a, errorMessage);
            return a - b;
        }
    }

    /**
     * @dev Returns the integer division of two unsigned integers, reverting with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        unchecked {
            require(b > 0, errorMessage);
            return a / b;
        }
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * reverting with custom message when dividing by zero.
     *
     * CAUTION: This function is deprecated because it requires allocating memory for the error
     * message unnecessarily. For custom revert reasons use {tryMod}.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        unchecked {
            require(b > 0, errorMessage);
            return a % b;
        }
    }
}


// File contracts/mocks/SafeMathMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract SafeMathMock {
    function tryAdd(uint256 a, uint256 b) public pure returns (bool flag, uint256 value) {
        return SafeMath.tryAdd(a, b);
    }

    function trySub(uint256 a, uint256 b) public pure returns (bool flag, uint256 value) {
        return SafeMath.trySub(a, b);
    }

    function tryMul(uint256 a, uint256 b) public pure returns (bool flag, uint256 value) {
        return SafeMath.tryMul(a, b);
    }

    function tryDiv(uint256 a, uint256 b) public pure returns (bool flag, uint256 value) {
        return SafeMath.tryDiv(a, b);
    }

    function tryMod(uint256 a, uint256 b) public pure returns (bool flag, uint256 value) {
        return SafeMath.tryMod(a, b);
    }

    // using the do* naming convention to avoid warnings due to clashing opcode names

    function doAdd(uint256 a, uint256 b) public pure returns (uint256) {
        return SafeMath.add(a, b);
    }

    function doSub(uint256 a, uint256 b) public pure returns (uint256) {
        return SafeMath.sub(a, b);
    }

    function doMul(uint256 a, uint256 b) public pure returns (uint256) {
        return SafeMath.mul(a, b);
    }

    function doDiv(uint256 a, uint256 b) public pure returns (uint256) {
        return SafeMath.div(a, b);
    }

    function doMod(uint256 a, uint256 b) public pure returns (uint256) {
        return SafeMath.mod(a, b);
    }

    function subWithMessage(uint256 a, uint256 b, string memory errorMessage) public pure returns (uint256) {
        return SafeMath.sub(a, b, errorMessage);
    }

    function divWithMessage(uint256 a, uint256 b, string memory errorMessage) public pure returns (uint256) {
        return SafeMath.div(a, b, errorMessage);
    }

    function modWithMessage(uint256 a, uint256 b, string memory errorMessage) public pure returns (uint256) {
        return SafeMath.mod(a, b, errorMessage);
    }

    function addMemoryCheck() public pure returns (uint256 mem) {
        uint256 length = 32;
        // solhint-disable-next-line no-inline-assembly
        assembly { mem := mload(0x40) }
        for (uint256 i = 0; i < length; ++i) { SafeMath.add(1, 1); }
        // solhint-disable-next-line no-inline-assembly
        assembly { mem := sub(mload(0x40), mem) }
    }

    function subMemoryCheck() public pure returns (uint256 mem) {
        uint256 length = 32;
        // solhint-disable-next-line no-inline-assembly
        assembly { mem := mload(0x40) }
        for (uint256 i = 0; i < length; ++i) { SafeMath.sub(1, 1); }
        // solhint-disable-next-line no-inline-assembly
        assembly { mem := sub(mload(0x40), mem) }
    }

    function mulMemoryCheck() public pure returns (uint256 mem) {
        uint256 length = 32;
        // solhint-disable-next-line no-inline-assembly
        assembly { mem := mload(0x40) }
        for (uint256 i = 0; i < length; ++i) { SafeMath.mul(1, 1); }
        // solhint-disable-next-line no-inline-assembly
        assembly { mem := sub(mload(0x40), mem) }
    }

    function divMemoryCheck() public pure returns (uint256 mem) {
        uint256 length = 32;
        // solhint-disable-next-line no-inline-assembly
        assembly { mem := mload(0x40) }
        for (uint256 i = 0; i < length; ++i) { SafeMath.div(1, 1); }
        // solhint-disable-next-line no-inline-assembly
        assembly { mem := sub(mload(0x40), mem) }
    }

    function modMemoryCheck() public pure returns (uint256 mem) {
        uint256 length = 32;
        // solhint-disable-next-line no-inline-assembly
        assembly { mem := mload(0x40) }
        for (uint256 i = 0; i < length; ++i) { SafeMath.mod(1, 1); }
        // solhint-disable-next-line no-inline-assembly
        assembly { mem := sub(mload(0x40), mem) }
    }

}


// File contracts/utils/math/SignedSafeMath.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev Wrappers over Solidity's arithmetic operations.
 *
 * NOTE: `SignedSafeMath` is no longer needed starting with Solidity 0.8. The compiler
 * now has built in overflow checking.
 */
library SignedSafeMath {
    /**
     * @dev Returns the multiplication of two signed integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     *
     * - Multiplication cannot overflow.
     */
    function mul(int256 a, int256 b) internal pure returns (int256) {
        return a * b;
    }

    /**
     * @dev Returns the integer division of two signed integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator.
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(int256 a, int256 b) internal pure returns (int256) {
        return a / b;
    }

    /**
     * @dev Returns the subtraction of two signed integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(int256 a, int256 b) internal pure returns (int256) {
        return a - b;
    }

    /**
     * @dev Returns the addition of two signed integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     *
     * - Addition cannot overflow.
     */
    function add(int256 a, int256 b) internal pure returns (int256) {
        return a + b;
    }
}


// File contracts/mocks/SignedSafeMathMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract SignedSafeMathMock {
    function mul(int256 a, int256 b) public pure returns (int256) {
        return SignedSafeMath.mul(a, b);
    }

    function div(int256 a, int256 b) public pure returns (int256) {
        return SignedSafeMath.div(a, b);
    }

    function sub(int256 a, int256 b) public pure returns (int256) {
        return SignedSafeMath.sub(a, b);
    }

    function add(int256 a, int256 b) public pure returns (int256) {
        return SignedSafeMath.add(a, b);
    }
}


// File contracts/mocks/SingleInheritanceInitializableMocks.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title MigratableMockV1
 * @dev This contract is a mock to test initializable functionality through migrations
 */
contract MigratableMockV1 is Initializable {
  uint256 public x;

  function initialize(uint256 value) public payable initializer {
    x = value;
  }
}

/**
 * @title MigratableMockV2
 * @dev This contract is a mock to test migratable functionality with params
 */
contract MigratableMockV2 is MigratableMockV1 {
  bool internal _migratedV2;
  uint256 public y;

  function migrate(uint256 value, uint256 anotherValue) public payable {
    require(!_migratedV2);
    x = value;
    y = anotherValue;
    _migratedV2 = true;
  }
}

/**
 * @title MigratableMockV3
 * @dev This contract is a mock to test migratable functionality without params
 */
contract MigratableMockV3 is MigratableMockV2 {
  bool internal _migratedV3;

  function migrate() public payable {
    require(!_migratedV3);
    uint256 oldX = x;
    x = y;
    y = oldX;
    _migratedV3 = true;
  }
}


// File contracts/mocks/StringsMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract StringsMock {
    function fromUint256(uint256 value) public pure returns (string memory) {
        return Strings.toString(value);
    }
    function fromUint256Hex(uint256 value) public pure returns (string memory) {
        return Strings.toHexString(value);
    }
    function fromUint256HexFixed(uint256 value, uint256 length) public pure returns (string memory) {
        return Strings.toHexString(value, length);
    }
}


// File contracts/proxy/Proxy.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev This abstract contract provides a fallback function that delegates all calls to another contract using the EVM
 * instruction `delegatecall`. We refer to the second contract as the _implementation_ behind the proxy, and it has to
 * be specified by overriding the virtual {_implementation} function.
 *
 * Additionally, delegation to the implementation can be triggered manually through the {_fallback} function, or to a
 * different contract through the {_delegate} function.
 *
 * The success and return data of the delegated call will be returned back to the caller of the proxy.
 */
abstract contract Proxy {
    /**
     * @dev Delegates the current call to `implementation`.
     *
     * This function does not return to its internall call site, it will return directly to the external caller.
     */
    function _delegate(address implementation) internal virtual {
        // solhint-disable-next-line no-inline-assembly
        assembly {
            // Copy msg.data. We take full control of memory in this inline assembly
            // block because it will not return to Solidity code. We overwrite the
            // Solidity scratch pad at memory position 0.
            calldatacopy(0, 0, calldatasize())

            // Call the implementation.
            // out and outsize are 0 because we don't know the size yet.
            let result := delegatecall(gas(), implementation, 0, calldatasize(), 0, 0)

            // Copy the returned data.
            returndatacopy(0, 0, returndatasize())

            switch result
            // delegatecall returns 0 on error.
            case 0 { revert(0, returndatasize()) }
            default { return(0, returndatasize()) }
        }
    }

    /**
     * @dev This is a virtual function that should be overriden so it returns the address to which the fallback function
     * and {_fallback} should delegate.
     */
    function _implementation() internal view virtual returns (address);

    /**
     * @dev Delegates the current call to the address returned by `_implementation()`.
     *
     * This function does not return to its internall call site, it will return directly to the external caller.
     */
    function _fallback() internal virtual {
        _beforeFallback();
        _delegate(_implementation());
    }

    /**
     * @dev Fallback function that delegates calls to the address returned by `_implementation()`. Will run if no other
     * function in the contract matches the call data.
     */
    fallback () external payable virtual {
        _fallback();
    }

    /**
     * @dev Fallback function that delegates calls to the address returned by `_implementation()`. Will run if call data
     * is empty.
     */
    receive () external payable virtual {
        _fallback();
    }

    /**
     * @dev Hook that is called before falling back to the implementation. Can happen as part of a manual `_fallback`
     * call, or as part of the Solidity `fallback` or `receive` functions.
     *
     * If overriden should call `super._beforeFallback()`.
     */
    function _beforeFallback() internal virtual {
    }
}


// File contracts/proxy/beacon/IBeacon.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

/**
 * @dev This is the interface that {BeaconProxy} expects of its beacon.
 */
interface IBeacon {
    /**
     * @dev Must return an address that can be used as a delegate call target.
     *
     * {BeaconProxy} will check that this address is a contract.
     */
    function implementation() external view returns (address);
}


// File contracts/proxy/beacon/BeaconProxy.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev This contract implements a proxy that gets the implementation address for each call from a {UpgradeableBeacon}.
 *
 * The beacon address is stored in storage slot `uint256(keccak256('eip1967.proxy.beacon')) - 1`, so that it doesn't
 * conflict with the storage layout of the implementation behind the proxy.
 *
 * _Available since v3.4._
 */
contract BeaconProxy is Proxy {
    /**
     * @dev The storage slot of the UpgradeableBeacon contract which defines the implementation for this proxy.
     * This is bytes32(uint256(keccak256('eip1967.proxy.beacon')) - 1)) and is validated in the constructor.
     */
    bytes32 private constant _BEACON_SLOT = 0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;

    /**
     * @dev Initializes the proxy with `beacon`.
     *
     * If `data` is nonempty, it's used as data in a delegate call to the implementation returned by the beacon. This
     * will typically be an encoded function call, and allows initializating the storage of the proxy like a Solidity
     * constructor.
     *
     * Requirements:
     *
     * - `beacon` must be a contract with the interface {IBeacon}.
     */
    constructor(address beacon, bytes memory data) payable {
        assert(_BEACON_SLOT == bytes32(uint256(keccak256("eip1967.proxy.beacon")) - 1));
        _setBeacon(beacon, data);
    }

    /**
     * @dev Returns the current beacon address.
     */
    function _beacon() internal view virtual returns (address beacon) {
        bytes32 slot = _BEACON_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            beacon := sload(slot)
        }
    }

    /**
     * @dev Returns the current implementation address of the associated beacon.
     */
    function _implementation() internal view virtual override returns (address) {
        return IBeacon(_beacon()).implementation();
    }

    /**
     * @dev Changes the proxy to use a new beacon.
     *
     * If `data` is nonempty, it's used as data in a delegate call to the implementation returned by the beacon.
     *
     * Requirements:
     *
     * - `beacon` must be a contract.
     * - The implementation returned by `beacon` must be a contract.
     */
    function _setBeacon(address beacon, bytes memory data) internal virtual {
        require(
            Address.isContract(beacon),
            "BeaconProxy: beacon is not a contract"
        );
        require(
            Address.isContract(IBeacon(beacon).implementation()),
            "BeaconProxy: beacon implementation is not a contract"
        );
        bytes32 slot = _BEACON_SLOT;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            sstore(slot, beacon)
        }

        if (data.length > 0) {
            Address.functionDelegateCall(_implementation(), data, "BeaconProxy: function call failed");
        }
    }
}


// File contracts/proxy/beacon/UpgradeableBeacon.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev This contract is used in conjunction with one or more instances of {BeaconProxy} to determine their
 * implementation contract, which is where they will delegate all function calls.
 *
 * An owner is able to change the implementation the beacon points to, thus upgrading the proxies that use this beacon.
 */
contract UpgradeableBeacon is IBeacon, Ownable {
    address private _implementation;

    /**
     * @dev Emitted when the implementation returned by the beacon is changed.
     */
    event Upgraded(address indexed implementation);

    /**
     * @dev Sets the address of the initial implementation, and the deployer account as the owner who can upgrade the
     * beacon.
     */
    constructor(address implementation_) {
        _setImplementation(implementation_);
    }

    /**
     * @dev Returns the current implementation address.
     */
    function implementation() public view virtual override returns (address) {
        return _implementation;
    }

    /**
     * @dev Upgrades the beacon to a new implementation.
     *
     * Emits an {Upgraded} event.
     *
     * Requirements:
     *
     * - msg.sender must be the owner of the contract.
     * - `newImplementation` must be a contract.
     */
    function upgradeTo(address newImplementation) public virtual onlyOwner {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /**
     * @dev Sets the implementation contract address for this beacon
     *
     * Requirements:
     *
     * - `newImplementation` must be a contract.
     */
    function _setImplementation(address newImplementation) private {
        require(Address.isContract(newImplementation), "UpgradeableBeacon: implementation is not a contract");
        _implementation = newImplementation;
    }
}


// File contracts/proxy/ERC1967/ERC1967Proxy.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev This contract implements an upgradeable proxy. It is upgradeable because calls are delegated to an
 * implementation address that can be changed. This address is stored in storage in the location specified by
 * https://eips.ethereum.org/EIPS/eip-1967[EIP1967], so that it doesn't conflict with the storage layout of the
 * implementation behind the proxy.
 *
 * Upgradeability is only provided internally through {_upgradeTo}. For an externally upgradeable proxy see
 * {TransparentUpgradeableProxy}.
 */
contract ERC1967Proxy is Proxy {
    /**
     * @dev Initializes the upgradeable proxy with an initial implementation specified by `_logic`.
     *
     * If `_data` is nonempty, it's used as data in a delegate call to `_logic`. This will typically be an encoded
     * function call, and allows initializating the storage of the proxy like a Solidity constructor.
     */
    constructor(address _logic, bytes memory _data) payable {
        assert(_IMPLEMENTATION_SLOT == bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1));
        _setImplementation(_logic);
        if(_data.length > 0) {
            Address.functionDelegateCall(_logic, _data);
        }
    }

    /**
     * @dev Emitted when the implementation is upgraded.
     */
    event Upgraded(address indexed implementation);

    /**
     * @dev Storage slot with the address of the current implementation.
     * This is the keccak-256 hash of "eip1967.proxy.implementation" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 private constant _IMPLEMENTATION_SLOT = 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;

    /**
     * @dev Returns the current implementation address.
     */
    function _implementation() internal view virtual override returns (address impl) {
        bytes32 slot = _IMPLEMENTATION_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            impl := sload(slot)
        }
    }

    /**
     * @dev Upgrades the proxy to a new implementation.
     *
     * Emits an {Upgraded} event.
     */
    function _upgradeTo(address newImplementation) internal virtual {
        _setImplementation(newImplementation);
        emit Upgraded(newImplementation);
    }

    /**
     * @dev Stores a new address in the EIP1967 implementation slot.
     */
    function _setImplementation(address newImplementation) private {
        require(Address.isContract(newImplementation), "ERC1967Proxy: new implementation is not a contract");

        bytes32 slot = _IMPLEMENTATION_SLOT;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            sstore(slot, newImplementation)
        }
    }
}


// File contracts/proxy/transparent/TransparentUpgradeableProxy.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev This contract implements a proxy that is upgradeable by an admin.
 *
 * To avoid https://medium.com/nomic-labs-blog/malicious-backdoors-in-ethereum-proxies-62629adf3357[proxy selector
 * clashing], which can potentially be used in an attack, this contract uses the
 * https://blog.openzeppelin.com/the-transparent-proxy-pattern/[transparent proxy pattern]. This pattern implies two
 * things that go hand in hand:
 *
 * 1. If any account other than the admin calls the proxy, the call will be forwarded to the implementation, even if
 * that call matches one of the admin functions exposed by the proxy itself.
 * 2. If the admin calls the proxy, it can access the admin functions, but its calls will never be forwarded to the
 * implementation. If the admin tries to call a function on the implementation it will fail with an error that says
 * "admin cannot fallback to proxy target".
 *
 * These properties mean that the admin account can only be used for admin actions like upgrading the proxy or changing
 * the admin, so it's best if it's a dedicated account that is not used for anything else. This will avoid headaches due
 * to sudden errors when trying to call a function from the proxy implementation.
 *
 * Our recommendation is for the dedicated account to be an instance of the {ProxyAdmin} contract. If set up this way,
 * you should think of the `ProxyAdmin` instance as the real administrative interface of your proxy.
 */
contract TransparentUpgradeableProxy is ERC1967Proxy {
    /**
     * @dev Initializes an upgradeable proxy managed by `_admin`, backed by the implementation at `_logic`, and
     * optionally initialized with `_data` as explained in {UpgradeableProxy-constructor}.
     */
    constructor(address _logic, address admin_, bytes memory _data) payable ERC1967Proxy(_logic, _data) {
        assert(_ADMIN_SLOT == bytes32(uint256(keccak256("eip1967.proxy.admin")) - 1));
        _setAdmin(admin_);
    }

    /**
     * @dev Emitted when the admin account has changed.
     */
    event AdminChanged(address previousAdmin, address newAdmin);

    /**
     * @dev Storage slot with the admin of the contract.
     * This is the keccak-256 hash of "eip1967.proxy.admin" subtracted by 1, and is
     * validated in the constructor.
     */
    bytes32 private constant _ADMIN_SLOT = 0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;

    /**
     * @dev Modifier used internally that will delegate the call to the implementation unless the sender is the admin.
     */
    modifier ifAdmin() {
        if (msg.sender == _admin()) {
            _;
        } else {
            _fallback();
        }
    }

    /**
     * @dev Returns the current admin.
     *
     * NOTE: Only the admin can call this function. See {ProxyAdmin-getProxyAdmin}.
     *
     * TIP: To get this value clients can read directly from the storage slot shown below (specified by EIP1967) using the
     * https://eth.wiki/json-rpc/API#eth_getstorageat[`eth_getStorageAt`] RPC call.
     * `0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103`
     */
    function admin() external ifAdmin returns (address admin_) {
        admin_ = _admin();
    }

    /**
     * @dev Returns the current implementation.
     *
     * NOTE: Only the admin can call this function. See {ProxyAdmin-getProxyImplementation}.
     *
     * TIP: To get this value clients can read directly from the storage slot shown below (specified by EIP1967) using the
     * https://eth.wiki/json-rpc/API#eth_getstorageat[`eth_getStorageAt`] RPC call.
     * `0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc`
     */
    function implementation() external ifAdmin returns (address implementation_) {
        implementation_ = _implementation();
    }

    /**
     * @dev Changes the admin of the proxy.
     *
     * Emits an {AdminChanged} event.
     *
     * NOTE: Only the admin can call this function. See {ProxyAdmin-changeProxyAdmin}.
     */
    function changeAdmin(address newAdmin) external virtual ifAdmin {
        require(newAdmin != address(0), "TransparentUpgradeableProxy: new admin is the zero address");
        emit AdminChanged(_admin(), newAdmin);
        _setAdmin(newAdmin);
    }

    /**
     * @dev Upgrade the implementation of the proxy.
     *
     * NOTE: Only the admin can call this function. See {ProxyAdmin-upgrade}.
     */
    function upgradeTo(address newImplementation) external virtual ifAdmin {
        _upgradeTo(newImplementation);
    }

    /**
     * @dev Upgrade the implementation of the proxy, and then call a function from the new implementation as specified
     * by `data`, which should be an encoded function call. This is useful to initialize new storage variables in the
     * proxied contract.
     *
     * NOTE: Only the admin can call this function. See {ProxyAdmin-upgradeAndCall}.
     */
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable virtual ifAdmin {
        _upgradeTo(newImplementation);
        Address.functionDelegateCall(newImplementation, data);
    }

    /**
     * @dev Returns the current admin.
     */
    function _admin() internal view virtual returns (address adm) {
        bytes32 slot = _ADMIN_SLOT;
        // solhint-disable-next-line no-inline-assembly
        assembly {
            adm := sload(slot)
        }
    }

    /**
     * @dev Stores a new address in the EIP1967 admin slot.
     */
    function _setAdmin(address newAdmin) private {
        bytes32 slot = _ADMIN_SLOT;

        // solhint-disable-next-line no-inline-assembly
        assembly {
            sstore(slot, newAdmin)
        }
    }

    /**
     * @dev Makes sure the admin cannot access the fallback function. See {Proxy-_beforeFallback}.
     */
    function _beforeFallback() internal virtual override {
        require(msg.sender != _admin(), "TransparentUpgradeableProxy: admin cannot fallback to proxy target");
        super._beforeFallback();
    }
}


// File contracts/proxy/transparent/ProxyAdmin.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev This is an auxiliary contract meant to be assigned as the admin of a {TransparentUpgradeableProxy}. For an
 * explanation of why you would want to use this see the documentation for {TransparentUpgradeableProxy}.
 */
contract ProxyAdmin is Ownable {

    /**
     * @dev Returns the current implementation of `proxy`.
     *
     * Requirements:
     *
     * - This contract must be the admin of `proxy`.
     */
    function getProxyImplementation(TransparentUpgradeableProxy proxy) public view virtual returns (address) {
        // We need to manually run the static call since the getter cannot be flagged as view
        // bytes4(keccak256("implementation()")) == 0x5c60da1b
        (bool success, bytes memory returndata) = address(proxy).staticcall(hex"5c60da1b");
        require(success);
        return abi.decode(returndata, (address));
    }

    /**
     * @dev Returns the current admin of `proxy`.
     *
     * Requirements:
     *
     * - This contract must be the admin of `proxy`.
     */
    function getProxyAdmin(TransparentUpgradeableProxy proxy) public view virtual returns (address) {
        // We need to manually run the static call since the getter cannot be flagged as view
        // bytes4(keccak256("admin()")) == 0xf851a440
        (bool success, bytes memory returndata) = address(proxy).staticcall(hex"f851a440");
        require(success);
        return abi.decode(returndata, (address));
    }

    /**
     * @dev Changes the admin of `proxy` to `newAdmin`.
     *
     * Requirements:
     *
     * - This contract must be the current admin of `proxy`.
     */
    function changeProxyAdmin(TransparentUpgradeableProxy proxy, address newAdmin) public virtual onlyOwner {
        proxy.changeAdmin(newAdmin);
    }

    /**
     * @dev Upgrades `proxy` to `implementation`. See {TransparentUpgradeableProxy-upgradeTo}.
     *
     * Requirements:
     *
     * - This contract must be the admin of `proxy`.
     */
    function upgrade(TransparentUpgradeableProxy proxy, address implementation) public virtual onlyOwner {
        proxy.upgradeTo(implementation);
    }

    /**
     * @dev Upgrades `proxy` to `implementation` and calls a function on the new implementation. See
     * {TransparentUpgradeableProxy-upgradeToAndCall}.
     *
     * Requirements:
     *
     * - This contract must be the admin of `proxy`.
     */
    function upgradeAndCall(TransparentUpgradeableProxy proxy, address implementation, bytes memory data) public payable virtual onlyOwner {
        proxy.upgradeToAndCall{value: msg.value}(implementation, data);
    }
}


// File contracts/tatum/BlockchainLaboratories721.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;
pragma experimental ABIEncoderV2;
contract BlockchainLaboratories721  is ERC721, ERC721Enumerable, ERC721URIStorage, Pausable, AccessControl, ERC721Burnable {
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    bool _publicMint;
    constructor(string memory name_, string memory symbol_, bool publicMint)
    ERC721(name_, symbol_)
    {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(MINTER_ROLE, _msgSender());
        _setupRole(PAUSER_ROLE, _msgSender());
        _publicMint = publicMint;
    }

    function pause() public {
        require(
            hasRole(PAUSER_ROLE, _msgSender()),
            "TatumGeneral721: must have pauser role to pause"
        );
        _pause();
    }

    function unpause() public {
        require(
            hasRole(PAUSER_ROLE, _msgSender()),
            "TatumGeneral721: must have pauser role to pause"
        );
        _unpause();
    }

    /**
      * @dev Function to mint tokens.
     * @param to The address that will receive the minted tokens.
     * @param tokenId The token id to mint.
     * @param uri The token URI of the minted token.
     * @return A boolean that indicates if the operation was successful.
     */
    function mintWithTokenURI(
        address to,
        uint256 tokenId,
        string memory uri
    ) public returns (bool) {
        if (!_publicMint) {
            require(
                hasRole(MINTER_ROLE, _msgSender()),
                "TatumGeneral721: must have minter role to mint"
            );
        }
        _safeMint(to, tokenId);
        _setTokenURI(tokenId, uri);
        return true;
    }

    /**
     * @dev Function to mint tokens. This helper function allows to mint multiple NFTs in 1 transaction.
     * @param to The address that will receive the minted tokens.
     * @param tokenId The token id to mint.
     * @param uri The token URI of the minted token.
     * @return A boolean that indicates if the operation was successful.
    */
    function mintMultiple(
        address[] memory to,
        uint256[] memory tokenId,
        string[] memory uri
    ) public returns (bool) {
        if (!_publicMint) {
            require(
                hasRole(MINTER_ROLE, _msgSender()),
                "TatumGeneral721: must have minter role to mint"
            );
        }
        for (uint256 i = 0; i < to.length; i++) {
            _safeMint(to[i], tokenId[i]);
            _setTokenURI(tokenId[i], uri[i]);
        }
        return true;
    }

    function safeTransfer(address to, uint256 tokenId, bytes calldata data) public virtual {
        super._safeTransfer(_msgSender(), to, tokenId, data);
    }

    function safeTransfer(address to, uint256 tokenId) public virtual {
        super._safeTransfer(_msgSender(), to, tokenId, "");
    }

    function _beforeTokenTransfer(address from, address to, uint256 tokenId)
    internal
    whenNotPaused
    override(ERC721, ERC721Enumerable)
    {
        super._beforeTokenTransfer(from, to, tokenId);
    }

    // The following functions are overrides required by Solidity.

    function _burn(uint256 tokenId) internal override(ERC721, ERC721URIStorage) {
        super._burn(tokenId);
    }

    function tokenURI(uint256 tokenId)
    public
    view
    override(ERC721, ERC721URIStorage)
    returns (string memory)
    {
        return super.tokenURI(tokenId);
    }

    function supportsInterface(bytes4 interfaceId)
    public
    view
    override(ERC721, ERC721Enumerable, AccessControl)
    returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}


// File contracts/tatum/custodial/CustodialFullTokenWallet.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract CustodialFullTokenWallet is Ownable {

    function onERC721Received(address, address, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    receive() external payable {
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable {
        if (contractType == 0) {
            IERC20(tokenAddress).transfer(recipient, amount);
        } else if (contractType == 1) {
            IERC721(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, "");
        } else if (contractType == 2) {
            IERC1155(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, amount, "");
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
                                - 2 - ERC1155
        @param spender - who will be able to spend the assets on behalf of the user
        @param amount - amount to be approved to spend in the asset based of the contractType
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256 amount, uint256 tokenId) public virtual {
        if (contractType == 0) {
            IERC20(tokenAddress).approve(spender, amount);
        } else if (contractType == 1) {
            IERC721(tokenAddress).approve(spender, tokenId);
        } else if (contractType == 2) {
            IERC1155(tokenAddress).setApprovalForAll(spender, true);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/CustodialFullTokenWalletWithBatch.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract CustodialFullTokenWalletWithBatch is Ownable {

    function onERC721Received(address, address, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    receive() external payable {
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable {
        if (contractType == 0) {
            IERC20(tokenAddress).transfer(recipient, amount);
        } else if (contractType == 1) {
            IERC721(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, "");
        } else if (contractType == 2) {
            IERC1155(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, amount, "");
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer any number of assets.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transferBatch(address[] memory tokenAddress, uint256[] memory contractType, address[] memory recipient, uint256[] memory amount, uint256[] memory tokenId) public payable {
        require(tokenAddress.length == contractType.length);
        require(recipient.length == contractType.length);
        require(recipient.length == amount.length);
        require(amount.length == tokenId.length);
        for (uint256 i = 0; i < tokenAddress.length; i++) {
            if (contractType[i] == 0) {
                IERC20(tokenAddress[i]).transfer(recipient[i], amount[i]);
            } else if (contractType[i] == 1) {
                IERC721(tokenAddress[i]).safeTransferFrom(address(this), recipient[i], tokenId[i], "");
            } else if (contractType[i] == 2) {
                IERC1155(tokenAddress[i]).safeTransferFrom(address(this), recipient[i], tokenId[i], amount[i], "");
            } else if (contractType[i] == 3) {
                payable(recipient[i]).transfer(amount[i]);
            } else {
                revert("Unsupported contract type");
            }
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
                                - 2 - ERC1155
        @param spender - who will be able to spend the assets on behalf of the user
        @param amount - amount to be approved to spend in the asset based of the contractType
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256 amount, uint256 tokenId) public virtual {
        if (contractType == 0) {
            IERC20(tokenAddress).approve(spender, amount);
        } else if (contractType == 1) {
            IERC721(tokenAddress).approve(spender, tokenId);
        } else if (contractType == 2) {
            IERC1155(tokenAddress).setApprovalForAll(spender, true);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/CustodialOwnable.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract CustodialOwnable is Context, Initializable {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    function init(address addr) public virtual initializer  {
        _owner = addr;
        emit OwnershipTransferred(address(0), addr);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view virtual returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(owner() == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}


// File contracts/tatum/custodial/CustodialWallet.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract CustodialWallet is CustodialOwnable {

    using SafeERC20 for IERC20;

    event TransferNativeAsset(address indexed recipient, uint256 indexed amount);

    function onERC721Received(address, address, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    receive() external payable {
    }

    function init(address owner) public override {
        CustodialOwnable.init(owner);
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable onlyOwner {
        if (contractType == 0) {
            IERC20(tokenAddress).safeTransfer(recipient, amount);
        } else if (contractType == 1) {
            IERC721(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, "");
        } else if (contractType == 2) {
            IERC1155(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, amount, "");
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
            emit TransferNativeAsset(recipient, amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer any number of assets.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transferBatch(address[] memory tokenAddress, uint256[] memory contractType, address[] memory recipient, uint256[] memory amount, uint256[] memory tokenId) public payable onlyOwner {
        require(tokenAddress.length == contractType.length);
        require(recipient.length == contractType.length);
        require(recipient.length == amount.length);
        require(amount.length == tokenId.length);
        for (uint256 i = 0; i < tokenAddress.length; i++) {
            if (contractType[i] == 0) {
                IERC20(tokenAddress[i]).safeTransfer(recipient[i], amount[i]);
            } else if (contractType[i] == 1) {
                IERC721(tokenAddress[i]).safeTransferFrom(address(this), recipient[i], tokenId[i], "");
            } else if (contractType[i] == 2) {
                IERC1155(tokenAddress[i]).safeTransferFrom(address(this), recipient[i], tokenId[i], amount[i], "");
            } else if (contractType[i] == 3) {
                payable(recipient[i]).transfer(amount[i]);
                emit TransferNativeAsset(recipient[i], amount[i]);
            } else {
                revert("Unsupported contract type");
            }
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
                                - 2 - ERC1155
        @param spender - who will be able to spend the assets on behalf of the user
        @param amount - amount to be approved to spend in the asset based of the contractType
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256 amount, uint256 tokenId) public virtual onlyOwner {
        if (contractType == 0) {
            IERC20(tokenAddress).approve(spender, amount);
        } else if (contractType == 1) {
            IERC721(tokenAddress).approve(spender, tokenId);
        } else if (contractType == 2) {
            IERC1155(tokenAddress).setApprovalForAll(spender, true);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/CustodialWalletFactory.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract CustodialWalletFactory {

    CustodialWallet private initialWallet;

    event Created(address addr);

    constructor () {
        initialWallet = new CustodialWallet();
    }

    function cloneNewWallet(address owner, uint256 count) public {
        for (uint256 i = 0; i < count; i++) {
            address payable clone = createClone(address(initialWallet));
            CustodialWallet(clone).init(owner);
            emit Created(clone);
        }
    }

    function createClone(address target) internal returns (address payable result) {
        bytes20 targetBytes = bytes20(target);
        assembly {
            let clone := mload(0x40)
            mstore(clone, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(clone, 0x14), targetBytes)
            mstore(add(clone, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            result := create(0, clone, 0x37)
        }
    }
}


// File contracts/tatum/custodial/CustodialWalletFactoryV2.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.7;
contract CustodialWalletFactoryV2 {

    using Clones for CustodialWalletFactoryV2;

    CustodialWallet private rawWallet;

    mapping(bytes32 => address) public wallets;

    event WalletDetails(address addr, address owner, uint256 index);
    event Created(address addr);

    constructor () {
        rawWallet = new CustodialWallet();
    }

    function getWallet(address owner, uint256 index) public view returns (address addr, bool exists, bytes32 salt) {
        salt = keccak256(abi.encodePacked(owner, index));
        addr = Clones.predictDeterministicAddress(address(rawWallet), salt);
        exists = wallets[salt] != address(0);
    }

    function getWallets(address owner, uint256[] memory index) public view returns (address[] memory addr, bool[] memory exists, bytes32[] memory salt) {
        for (uint256 i = 0; i < index.length; i++) {
            salt[i] = keccak256(abi.encodePacked(owner, index[i]));
            addr[i] = Clones.predictDeterministicAddress(address(rawWallet), salt[i]);
            exists[i] = wallets[salt[i]] != address(0);
        }
        return (addr, exists, salt);
    }

    function create(address owner, uint256[] memory index) public {
        for (uint256 i = 0; i < index.length; i++) {
            (address calculatedAddress, bool exists, bytes32 salt) = getWallet(owner, index[i]);
            require(!exists, "Wallet already exists");
            address addr = Clones.cloneDeterministic(address(rawWallet), salt);
            require(addr == calculatedAddress, "Address doesnt match with predicted address.");

            wallets[salt] = addr;
            CustodialWallet(payable(addr)).init(owner);
            emit Created(addr);
            emit WalletDetails(addr, owner, index[i]);
        }
    }

    function create(address owner, uint256 index) public {
        (address calculatedAddress, bool exists, bytes32 salt) = getWallet(owner, index);
        require(!exists, "Wallet already exists");
        address addr = Clones.cloneDeterministic(address(rawWallet), salt);
        require(addr == calculatedAddress, "Address doesnt match with predicted address.");

        wallets[salt] = addr;
        CustodialWallet(payable(addr)).init(owner);
        emit Created(addr);
        emit WalletDetails(addr, owner, index);
    }
}


// File contracts/tatum/custodial/Custodial_1155_TokenWallet.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Custodial_1155_TokenWallet is Ownable {

    function onERC1155Received(address, address, uint256, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    receive() external payable {
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable {
        if (contractType == 2) {
            IERC1155(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, amount, "");
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 2 - ERC1155
        @param spender - who will be able to spend the assets on behalf of the user
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256, uint256) public virtual {
        if (contractType == 2) {
            IERC1155(tokenAddress).setApprovalForAll(spender, true);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/Custodial_1155_TokenWalletWithBatch.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Custodial_1155_TokenWalletWithBatch is Ownable {

    function onERC1155Received(address, address, uint256, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    receive() external payable {
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable {
        if (contractType == 2) {
            IERC1155(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, amount, "");
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer any number of assets.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transferBatch(address[] memory tokenAddress, uint256[] memory contractType, address[] memory recipient, uint256[] memory amount, uint256[] memory tokenId) public payable {
        require(tokenAddress.length == contractType.length);
        require(recipient.length == contractType.length);
        require(recipient.length == amount.length);
        require(amount.length == tokenId.length);
        for (uint256 i = 0; i < tokenAddress.length; i++) {
            if (contractType[i] == 2) {
                IERC1155(tokenAddress[i]).safeTransferFrom(address(this), recipient[i], tokenId[i], amount[i], "");
            } else if (contractType[i] == 3) {
                payable(recipient[i]).transfer(amount[i]);
            } else {
                revert("Unsupported contract type");
            }
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 2 - ERC1155
        @param spender - who will be able to spend the assets on behalf of the user
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256, uint256) public virtual {
        if (contractType == 2) {
            IERC1155(tokenAddress).setApprovalForAll(spender, true);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/Custodial_20_1155_TokenWallet.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Custodial_20_1155_TokenWallet is Ownable {

    function onERC1155Received(address, address, uint256, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    receive() external payable {
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable {
        if (contractType == 0) {
            IERC20(tokenAddress).transfer(recipient, amount);
        } else if (contractType == 2) {
            IERC1155(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, amount, "");
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 0 - ERC20
                                - 2 - ERC1155
        @param spender - who will be able to spend the assets on behalf of the user
        @param amount - amount to be approved to spend in the asset based of the contractType
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256 amount, uint256) public virtual {
        if (contractType == 0) {
            IERC20(tokenAddress).approve(spender, amount);
        } else if (contractType == 2) {
            IERC1155(tokenAddress).setApprovalForAll(spender, true);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/Custodial_20_1155_TokenWalletWithBatch.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Custodial_20_1155_TokenWalletWithBatch is Ownable {

    function onERC1155Received(address, address, uint256, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    receive() external payable {
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable {
        if (contractType == 0) {
            IERC20(tokenAddress).transfer(recipient, amount);
        } else if (contractType == 2) {
            IERC1155(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, amount, "");
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer any number of assets.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transferBatch(address[] memory tokenAddress, uint256[] memory contractType, address[] memory recipient, uint256[] memory amount, uint256[] memory tokenId) public payable {
        require(tokenAddress.length == contractType.length);
        require(recipient.length == contractType.length);
        require(recipient.length == amount.length);
        require(amount.length == tokenId.length);
        for (uint256 i = 0; i < tokenAddress.length; i++) {
            if (contractType[i] == 0) {
                IERC20(tokenAddress[i]).transfer(recipient[i], amount[i]);
            } else if (contractType[i] == 2) {
                IERC1155(tokenAddress[i]).safeTransferFrom(address(this), recipient[i], tokenId[i], amount[i], "");
            } else if (contractType[i] == 3) {
                payable(recipient[i]).transfer(amount[i]);
            } else {
                revert("Unsupported contract type");
            }
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 0 - ERC20
                                - 2 - ERC1155
        @param spender - who will be able to spend the assets on behalf of the user
        @param amount - amount to be approved to spend in the asset based of the contractType
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256 amount, uint256) public virtual {
        if (contractType == 0) {
            IERC20(tokenAddress).approve(spender, amount);
        } else if (contractType == 2) {
            IERC1155(tokenAddress).setApprovalForAll(spender, true);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/Custodial_20_721_TokenWallet.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Custodial_20_721_TokenWallet is Ownable {

    receive() external payable {
    }

    function onERC721Received(address, address, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }
    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable {
        if (contractType == 0) {
            IERC20(tokenAddress).transfer(recipient, amount);
        } else if (contractType == 1) {
            IERC721(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, "");
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
        @param spender - who will be able to spend the assets on behalf of the user
        @param amount - amount to be approved to spend in the asset based of the contractType
        @param tokenId - tokenId to transfer, valid only for ERC721
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256 amount, uint256 tokenId) public virtual {
        if (contractType == 0) {
            IERC20(tokenAddress).approve(spender, amount);
        } else if (contractType == 1) {
            IERC721(tokenAddress).approve(spender, tokenId);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/Custodial_20_721_TokenWalletWithBatch.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Custodial_20_721_TokenWalletWithBatch is Ownable {

    receive() external payable {
    }

    function onERC721Received(address, address, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }
    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable {
        if (contractType == 0) {
            IERC20(tokenAddress).transfer(recipient, amount);
        } else if (contractType == 1) {
            IERC721(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, "");
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer any number of assets.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721
    **/
    function transferBatch(address[] memory tokenAddress, uint256[] memory contractType, address[] memory recipient, uint256[] memory amount, uint256[] memory tokenId) public payable {
        require(tokenAddress.length == contractType.length);
        require(recipient.length == contractType.length);
        require(recipient.length == amount.length);
        require(recipient.length == tokenId.length);
        for (uint256 i = 0; i < tokenAddress.length; i++) {
            if (contractType[i] == 0) {
                IERC20(tokenAddress[i]).transfer(recipient[i], amount[i]);
            } else if (contractType[i] == 1) {
                IERC721(tokenAddress[i]).safeTransferFrom(address(this), recipient[i], tokenId[i], "");
            } else if (contractType[i] == 3) {
                payable(recipient[i]).transfer(amount[i]);
            } else {
                revert("Unsupported contract type");
            }
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
        @param spender - who will be able to spend the assets on behalf of the user
        @param amount - amount to be approved to spend in the asset based of the contractType
        @param tokenId - tokenId to transfer, valid only for ERC721
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256 amount, uint256 tokenId) public virtual {
        if (contractType == 0) {
            IERC20(tokenAddress).approve(spender, amount);
        } else if (contractType == 1) {
            IERC721(tokenAddress).approve(spender, tokenId);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/Custodial_20_TokenWallet.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Custodial_20_TokenWallet is Ownable {

    receive() external payable {
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256) public payable {
        if (contractType == 0) {
            IERC20(tokenAddress).transfer(recipient, amount);
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 0 - ERC20
        @param spender - who will be able to spend the assets on behalf of the user
        @param amount - amount to be approved to spend in the asset based of the contractType
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256 amount, uint256) public virtual {
        if (contractType == 0) {
            IERC20(tokenAddress).approve(spender, amount);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/Custodial_20_TokenWalletWithBatch.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Custodial_20_TokenWalletWithBatch is Ownable {

    receive() external payable {
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256) public payable {
        if (contractType == 0) {
            IERC20(tokenAddress).transfer(recipient, amount);
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer any number of assets.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType
    **/
    function transferBatch(address[] memory tokenAddress, uint256[] memory contractType, address[] memory recipient, uint256[] memory amount, uint256[] memory) public payable {
        require(tokenAddress.length == contractType.length);
        require(recipient.length == contractType.length);
        require(recipient.length == amount.length);
        for (uint256 i = 0; i < tokenAddress.length; i++) {
            if (contractType[i] == 0) {
                IERC20(tokenAddress[i]).transfer(recipient[i], amount[i]);
            } else if (contractType[i] == 3) {
                payable(recipient[i]).transfer(amount[i]);
            } else {
                revert("Unsupported contract type");
            }
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 0 - ERC20
        @param spender - who will be able to spend the assets on behalf of the user
        @param amount - amount to be approved to spend in the asset based of the contractType
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256 amount, uint256) public virtual {
        if (contractType == 0) {
            IERC20(tokenAddress).approve(spender, amount);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/Custodial_721_1155_TokenWallet.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Custodial_721_1155_TokenWallet is Ownable {

    function onERC721Received(address, address, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    receive() external payable {
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 1 - ERC721
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable {
        if (contractType == 1) {
            IERC721(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, "");
        } else if (contractType == 2) {
            IERC1155(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, amount, "");
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 1 - ERC721
                                - 2 - ERC1155
        @param spender - who will be able to spend the assets on behalf of the user
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256, uint256 tokenId) public virtual {
        if (contractType == 1) {
            IERC721(tokenAddress).approve(spender, tokenId);
        } else if (contractType == 2) {
            IERC1155(tokenAddress).setApprovalForAll(spender, true);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/Custodial_721_1155_TokenWalletWithBatch.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Custodial_721_1155_TokenWalletWithBatch is Ownable {

    function onERC721Received(address, address, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }

    function onERC1155Received(address, address, uint256, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory) public virtual returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    receive() external payable {
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 1 - ERC721
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable {
        if (contractType == 1) {
            IERC721(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, "");
        } else if (contractType == 2) {
            IERC1155(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, amount, "");
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer any number of assets.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 1 - ERC721
                                - 2 - ERC1155
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transferBatch(address[] memory tokenAddress, uint256[] memory contractType, address[] memory recipient, uint256[] memory amount, uint256[] memory tokenId) public payable {
        require(tokenAddress.length == contractType.length);
        require(recipient.length == contractType.length);
        require(recipient.length == amount.length);
        require(amount.length == tokenId.length);
        for (uint256 i = 0; i < tokenAddress.length; i++) {
            if (contractType[i] == 1) {
                IERC721(tokenAddress[i]).safeTransferFrom(address(this), recipient[i], tokenId[i], "");
            } else if (contractType[i] == 2) {
                IERC1155(tokenAddress[i]).safeTransferFrom(address(this), recipient[i], tokenId[i], amount[i], "");
            } else if (contractType[i] == 3) {
                payable(recipient[i]).transfer(amount[i]);
            } else {
                revert("Unsupported contract type");
            }
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 1 - ERC721
                                - 2 - ERC1155
        @param spender - who will be able to spend the assets on behalf of the user
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256, uint256 tokenId) public virtual {
        if (contractType == 1) {
            IERC721(tokenAddress).approve(spender, tokenId);
        } else if (contractType == 2) {
            IERC1155(tokenAddress).setApprovalForAll(spender, true);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/Custodial_721_TokenWallet.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Custodial_721_TokenWallet is Ownable {

    function onERC721Received(address, address, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }

    receive() external payable {
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 1 - ERC721
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable {
        if (contractType == 1) {
            IERC721(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, "");
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 1 - ERC721
        @param spender - who will be able to spend the assets on behalf of the user
        @param tokenId - tokenId to transfer, valid only for ERC721
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256, uint256 tokenId) public virtual {
        if (contractType == 1) {
            IERC721(tokenAddress).approve(spender, tokenId);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/Custodial_721_TokenWalletWithBatch.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Custodial_721_TokenWalletWithBatch is Ownable {

    function onERC721Received(address, address, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }

    receive() external payable {
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 1 - ERC721
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable {
        if (contractType == 1) {
            IERC721(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, "");
        } else if (contractType == 3) {
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer any number of assets.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 1 - ERC721
                                - 23- native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721
    **/
    function transferBatch(address[] memory tokenAddress, uint256[] memory contractType, address[] memory recipient, uint256[] memory amount, uint256[] memory tokenId) public payable {
        require(tokenAddress.length == contractType.length);
        require(recipient.length == contractType.length);
        require(recipient.length == amount.length);
        require(tokenId.length == amount.length);
        for (uint256 i = 0; i < tokenAddress.length; i++) {
            if (contractType[i] == 1) {
                IERC721(tokenAddress[i]).safeTransferFrom(address(this), recipient[i], tokenId[i], "");
            } else if (contractType[i] == 3) {
                payable(recipient[i]).transfer(amount[i]);
            } else {
                revert("Unsupported contract type");
            }
        }
    }

    /**
        Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 1 - ERC721
        @param spender - who will be able to spend the assets on behalf of the user
        @param tokenId - tokenId to transfer, valid only for ERC721
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256, uint256 tokenId) public virtual {
        if (contractType == 1) {
            IERC721(tokenAddress).approve(spender, tokenId);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/TronCustodialWallet.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
interface TRC721 {
    // Returns the number of NFTs owned by the given account
    function balanceOf(address _owner) external view returns (uint256);

    //Returns the owner of the given NFT
    function ownerOf(uint256 _tokenId) external view returns (address);

    //Transfer ownership of NFT
    function safeTransferFrom(address _from, address _to, uint256 _tokenId, bytes memory data) external payable;

    //Transfer ownership of NFT
    function safeTransferFrom(address _from, address _to, uint256 _tokenId) external payable;

    //Transfer ownership of NFT
    function transferFrom(address _from, address _to, uint256 _tokenId) external payable;

    //Grants address ‘_approved’ the authorization of the NFT ‘_tokenId’
    function approve(address _approved, uint256 _tokenId) external payable;

    //Grant/recover all NFTs’ authorization of the ‘_operator’
    function setApprovalForAll(address _operator, bool _approved) external;

    //Query the authorized address of NFT
    function getApproved(uint256 _tokenId) external view returns (address);

    //Query whether the ‘_operator’ is the authorized address of the ‘_owner’
    function isApprovedForAll(address _owner, address _operator) external view returns (bool);

    //The successful ‘transferFrom’ and ‘safeTransferFrom’ will trigger the ‘Transfer’ Event
    event Transfer(address indexed _from, address indexed _to, uint256 indexed _tokenId);

    //The successful ‘Approval’ will trigger the ‘Approval’ event
    event Approval(address indexed _owner, address indexed _approved, uint256 indexed _tokenId);

    //The successful ‘setApprovalForAll’ will trigger the ‘ApprovalForAll’ event
    event ApprovalForAll(address indexed _owner, address indexed _operator, bool _approved);

}

contract TronCustodialWallet is CustodialOwnable {

    event TransferNativeAsset(address indexed recipient, uint256 indexed amount);
    
    function onTRC721Received(address, address, uint256, bytes memory) public virtual returns (bytes4) {
        return this.onTRC721Received.selector;
    }

    receive() external payable {
    }

    function init(address owner) public override {
        CustodialOwnable.init(owner);
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer only 1 type of asset.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transfer(address tokenAddress, uint256 contractType, address recipient, uint256 amount, uint256 tokenId) public payable onlyOwner {
        if (contractType == 0) {
            IERC20(tokenAddress).transfer(recipient, amount);
        } else if (contractType == 1) {
            TRC721(tokenAddress).safeTransferFrom(address(this), recipient, tokenId, "");
        } else if (contractType == 3) {
            emit TransferNativeAsset(recipient, amount);
            payable(recipient).transfer(amount);
        } else {
            revert("Unsupported contract type");
        }
    }

    /**
        Function transfer assets owned by this wallet to the recipient. Transfer any number of assets.
        @param tokenAddress - address of the asset to own, if transferring native asset, use 0x0000000 address
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
                                - 3 - native asset
        @param recipient - recipient of the transaction
        @param amount - amount to be transferred in the asset based of the contractType, for ERC721 not important
        @param tokenId - tokenId to transfer, valid only for ERC721 and ERC1155
    **/
    function transferBatch(address[] memory tokenAddress, uint256[] memory contractType, address[] memory recipient, uint256[] memory amount, uint256[] memory tokenId) public payable onlyOwner {
        require(tokenAddress.length == contractType.length);
        require(recipient.length == contractType.length);
        require(recipient.length == amount.length);
        require(amount.length == tokenId.length);
        for (uint256 i = 0; i < tokenAddress.length; i++) {
            if (contractType[i] == 0) {
                IERC20(tokenAddress[i]).transfer(recipient[i], amount[i]);
            } else if (contractType[i] == 1) {
                TRC721(tokenAddress[i]).safeTransferFrom(address(this), recipient[i], tokenId[i], "");
            } else if (contractType[i] == 3) {
                payable(recipient[i]).transfer(amount[i]);
                emit TransferNativeAsset(recipient[i], amount[i]);
            } else {
                revert("Unsupported contract type");
            }
        }
    }

    /**
       Function approves the transfer of assets owned by this wallet to the spender. Approve only 1 type of asset.
        @param tokenAddress - address of the asset to approve
        @param contractType - type of asset
                                - 0 - ERC20
                                - 1 - ERC721
        @param spender - who will be able to spend the assets on behalf of the user
        @param amount - amount to be approved to spend in the asset based of the contractType
        @param tokenId - tokenId to transfer, valid only for ERC721 
    **/
    function approve(address tokenAddress, uint256 contractType, address spender, uint256 amount, uint256 tokenId) public virtual onlyOwner {
        if (contractType == 0) {
            IERC20(tokenAddress).approve(spender, amount);
        } else if (contractType == 1) {
            TRC721(tokenAddress).approve(spender, tokenId);
        } else {
            revert("Unsupported contract type");
        }
    }
}


// File contracts/tatum/custodial/TronCustodialWalletFactory.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
contract TronTronCustodialWalletFactory {

    TronCustodialWallet private initialWallet;

    event Created(address addr);

    constructor () {
        initialWallet = new TronCustodialWallet();
    }

    function cloneNewWallet(address owner, uint256 count) public {
        for (uint256 i = 0; i < count; i++) {
            address payable clone = createClone(address(initialWallet));
            TronCustodialWallet(clone).init(owner);
            emit Created(clone);
        }
    }

    function createClone(address target) internal returns (address payable result) {
        bytes20 targetBytes = bytes20(target);
        assembly {
            let clone := mload(0x40)
            mstore(clone, 0x3d602d80600a3d3981f3363d3d373d3d3d363d73000000000000000000000000)
            mstore(add(clone, 0x14), targetBytes)
            mstore(add(clone, 0x28), 0x5af43d82803e903d91602b57fd5bf30000000000000000000000000000000000)
            result := create(0, clone, 0x37)
        }
    }
}


// File contracts/tatum/nft/MarketplaceListing.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;
contract Tatum {
    function tokenCashbackValues(uint256 tokenId, uint256 tokenPrice)
    public
    view
    virtual
    returns (uint256[] memory)
    {}

    function getCashbackAddress(uint256 tokenId)
    public
    view
    virtual
    returns (address)
    {}
}

contract MarketplaceListing is Ownable {
    using Address for address;

    enum State {
        INITIATED,
        SOLD,
        CANCELLED
    }

    struct Listing {
        string listingId;
        bool isErc721;
        State state;
        address nftAddress;
        address seller;
        address erc20Address;
        uint256 tokenId;
        uint256 amount;
        uint256 price;
        address buyer;
    }

    // List of all listings in the marketplace. All historical ones are here as well.
    mapping(string => Listing) private _listings;
    string[] private _openListings;
    uint256 private _marketplaceFee;
    address private _marketplaceFeeRecipient;
    /**
     * @dev Emitted when new listing is created by the owner of the contract. Amount is valid only for ERC-1155 tokens
     */
    event ListingCreated(
        bool indexed isErc721,
        address indexed nftAddress,
        uint256 indexed tokenId,
        string listingId,
        uint256 amount,
        uint256 price,
        address erc20Address
    );

    /**
     * @dev Emitted when listing assets were sold.
     */
    event ListingSold(address indexed buyer, string listingId);

    /**
     * @dev Emitted when listing was cancelled and assets were returned to the seller.
     */
    event ListingCancelled(string listingId);

    receive() external payable {}

    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes memory
    ) public virtual returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] memory,
        uint256[] memory,
        bytes memory
    ) public virtual returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }

    constructor(uint256 fee, address feeRecipient) {
        _marketplaceFee = fee;
        _marketplaceFeeRecipient = feeRecipient;
    }

    function getMarketplaceFee() public view virtual returns (uint256) {
        return _marketplaceFee;
    }

    function getMarketplaceFeeRecipient()
    public
    view
    virtual
    returns (address)
    {
        return _marketplaceFeeRecipient;
    }

    function getListing(string memory listingId)
    public
    view
    virtual
    returns (Listing memory)
    {
        return _listings[listingId];
    }

    function getOpenListings()
    public
    view
    virtual
    returns (string[] memory)
    {
        return _openListings;
    }

    function setMarketplaceFee(uint256 fee) public virtual onlyOwner {
        _marketplaceFee = fee;
    }

    function setMarketplaceFeeRecipient(address recipient)
    public
    virtual
    onlyOwner
    {
        _marketplaceFeeRecipient = recipient;
    }

    /**
     * @dev Create new listing of the NFT token in the marketplace.
     * @param listingId - ID of the listing, must be unique
     * @param isErc721 - whether the listing is for ERC721 or ERC1155 token
     * @param nftAddress - address of the NFT token
     * @param tokenId - ID of the NFT token
     * @param price - Price for the token. It could be in wei or smallest ERC20 value, if @param erc20Address is not 0x0 address
     * @param amount - ERC1155 only, number of tokens to sold.
     * @param erc20Address - address of the ERC20 token, which will be used for the payment. If native asset is used, this should be 0x0 address
     */
    function createListing(
        string memory listingId,
        bool isErc721,
        address nftAddress,
        uint256 tokenId,
        uint256 price,
        address seller,
        uint256 amount,
        address erc20Address
    ) public payable {
        if (
            keccak256(abi.encodePacked(_listings[listingId].listingId)) ==
            keccak256(abi.encodePacked(listingId))
        ) {
            revert("Listing already existed for current listing Id");
        }
        if (!isErc721) {
            require(amount > 0);
            require(
                IERC1155(nftAddress).balanceOf(seller, tokenId) >= amount,
                "ERC1155 token balance is not sufficient for the seller.."
            );
        } else {
            require(
                IERC721(nftAddress).ownerOf(tokenId) == seller,
                "ERC721 token does not belong to the author."
            );
            if (_isTatumNFT(nftAddress, tokenId)) {
                if (Tatum(nftAddress).getCashbackAddress(tokenId) == address(0)) {
                    uint256 cashbackSum = 0;
                    uint256[] memory cashback = Tatum(nftAddress)
                    .tokenCashbackValues(tokenId, price);
                    for (uint256 j = 0; j < cashback.length; j++) {
                        cashbackSum += cashback[j];
                    }
                    require(
                        msg.value >= cashbackSum,
                        "Balance Insufficient to pay royalties"
                    );
                    Address.sendValue(payable(address(this)), cashbackSum);
                    if (msg.value > cashbackSum) {
                        Address.sendValue(
                            payable(msg.sender),
                            msg.value - cashbackSum
                        );
                    }
                }
            }
        }
        Listing memory listing = Listing(
            listingId,
            isErc721,
            State.INITIATED,
            nftAddress,
            seller,
            erc20Address,
            tokenId,
            amount,
            price,
            address(0)
        );
        _listings[listingId] = listing;
        _openListings.push(listingId);
        emit ListingCreated(
            isErc721,
            nftAddress,
            tokenId,
            listingId,
            amount,
            price,
            erc20Address
        );
    }

    /**
     * @dev Buyer wants to buy NFT from listing. All the required checks must pass.
     * Buyer must either send ETH with this endpoint, or ERC20 tokens will be deducted from his account to the marketplace contract.
     * @param listingId - id of the listing to buy
     * @param erc20Address - optional address of the ERC20 token to pay for the assets, if listing is listed in ERC20
     */
    function buyAssetFromListing(string memory listingId, address erc20Address)
    public
    payable
    {
        Listing memory listing = _listings[listingId];
        if (listing.state != State.INITIATED) {
            if (msg.value > 0) {
                Address.sendValue(payable(msg.sender), msg.value);
            }
            revert("Listing is in wrong state. Aborting.");
        }
        if (listing.isErc721) {
            if (
                IERC721(listing.nftAddress).getApproved(listing.tokenId) !=
                address(this)
            ) {
                if (msg.value > 0) {
                    Address.sendValue(payable(msg.sender), msg.value);
                }
                revert(
                "Asset is not owned by this listing. Probably was not sent to the smart contract, or was already sold."
                );
            }
        } else {
            if (
                IERC1155(listing.nftAddress).balanceOf(
                    listing.seller,
                    listing.tokenId
                ) < listing.amount
            ) {
                if (msg.value > 0) {
                    Address.sendValue(payable(msg.sender), msg.value);
                }
                revert(
                "Insufficient balance of the asset in this listing. Probably was not sent to the smart contract, or was already sold."
                );
            }
        }
        if (listing.erc20Address != erc20Address) {
            if (msg.value > 0) {
                Address.sendValue(payable(msg.sender), msg.value);
            }
            revert(
            "ERC20 token address as a payer method should be the same as in the listing. Either listing, or method call has wrong ERC20 address."
            );
        }
        uint256 fee = (listing.price * _marketplaceFee) / 10000;
        listing.state = State.SOLD;
        listing.buyer = msg.sender;
        _listings[listingId] = listing;
        uint256 cashbackSum = 0;
        if (listing.isErc721) {
            if (_isTatumNFT(listing.nftAddress, listing.tokenId)) {
                if (
                    Tatum(listing.nftAddress).getCashbackAddress(listing.tokenId) ==
                    address(0)
                ) {
                    uint256[] memory cashback = Tatum(listing.nftAddress)
                    .tokenCashbackValues(listing.tokenId, listing.price);
                    for (uint256 j = 0; j < cashback.length; j++) {
                        cashbackSum += cashback[j];
                    }
                }
            }
        }
        if (listing.erc20Address == address(0)) {
            if (listing.price + fee > msg.value) {
                if (msg.value > 0) {
                    Address.sendValue(payable(msg.sender), msg.value);
                }
                revert("Insufficient price paid for the asset.");
            }
            Address.sendValue(payable(_marketplaceFeeRecipient), fee);
            Address.sendValue(payable(listing.seller), listing.price);
            // Overpaid price is returned back to the sender
            if (msg.value - listing.price - fee > 0) {
                Address.sendValue(
                    payable(msg.sender),
                    msg.value - listing.price - fee
                );
            }
            if (listing.isErc721) {
                IERC721(listing.nftAddress).safeTransferFrom{
                value : cashbackSum
                }(
                    listing.seller,
                    msg.sender,
                    listing.tokenId,
                    abi.encodePacked(
                        "SafeTransferFrom",
                        "'''###'''",
                        _uint2str(listing.price)
                    )
                );
            } else {
                IERC1155(listing.nftAddress).safeTransferFrom(
                    listing.seller,
                    msg.sender,
                    listing.tokenId,
                    listing.amount,
                    ""
                );
            }
        } else {
            IERC20 token = IERC20(listing.erc20Address);
            if (
                listing.price + fee > token.allowance(msg.sender, address(this))
            ) {
                if (msg.value > 0) {
                    Address.sendValue(payable(msg.sender), msg.value);
                }
                revert(
                "Insufficient ERC20 allowance balance for paying for the asset."
                );
            }
            token.transferFrom(msg.sender, _marketplaceFeeRecipient, fee);
            token.transferFrom(msg.sender, listing.seller, listing.price);
            if (msg.value > 0) {
                Address.sendValue(payable(msg.sender), msg.value);
            }
            if (listing.isErc721) {
                bytes memory bytesInput = abi.encodePacked(
                    "CUSTOMTOKEN0x",
                    _toAsciiString(listing.erc20Address),
                    "'''###'''",
                    _uint2str(listing.price)
                );
                IERC721(listing.nftAddress).safeTransferFrom{
                value : cashbackSum
                }(listing.seller, msg.sender, listing.tokenId, bytesInput);
            } else {
                IERC1155(listing.nftAddress).safeTransferFrom(
                    listing.seller,
                    msg.sender,
                    listing.tokenId,
                    listing.amount,
                    ""
                );
            }
        }
        _toRemove(listingId);
        emit ListingSold(msg.sender, listingId);
    }

    function _toRemove(string memory listingId) internal {
        for (uint x = 0; x < _openListings.length; x++) {
            if (
                keccak256(abi.encodePacked(_openListings[x])) ==
                keccak256(abi.encodePacked(listingId))
            ) {
                for (uint i = x; i < _openListings.length - 1; i++) {
                    _openListings[i] = _openListings[i + 1];
                }
                _openListings.pop();
            }
        }
    }

    function _toAsciiString(address x) internal pure returns (bytes memory) {
        bytes memory s = new bytes(40);
        for (uint256 i = 0; i < 20; i++) {
            bytes1 b = bytes1(uint8(uint256(uint160(x)) / (2 ** (8 * (19 - i)))));
            bytes1 hi = bytes1(uint8(b) / 16);
            bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
            s[2 * i] = _char(hi);
            s[2 * i + 1] = _char(lo);
        }
        return s;
    }

    function _char(bytes1 b) internal pure returns (bytes1 c) {
        if (uint8(b) < 10) return bytes1(uint8(b) + 0x30);
        else return bytes1(uint8(b) + 0x57);
    }

    function _uint2str(uint256 _i)
    internal
    pure
    returns (string memory _uintAsString)
    {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint256 k = len;
        while (_i != 0) {
            k = k - 1;
            uint8 temp = (48 + uint8(_i - (_i / 10) * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }

    /**
     * @dev Buyer wants to buy NFT from listing. All the required checks must pass.
     * Buyer must approve spending of the ERC20 tokens will be deducted from his account to the marketplace contract.
     * @param listingId - id of the listing to buy
     * @param erc20Address - optional address of the ERC20 token to pay for the assets
     * @param buyer - buyer of the item, from which account the ERC20 assets will be debited
     */
    function buyAssetFromListingForExternalBuyer(
        string memory listingId,
        address erc20Address,
        address buyer
    ) public payable {
        Listing memory listing = _listings[listingId];
        if (listing.state != State.INITIATED) {
            revert("Listing is in wrong state. Aborting.");
        }
        if (listing.isErc721) {
            if (
                IERC721(listing.nftAddress).getApproved(listing.tokenId) !=
                address(this)
            ) {
                revert(
                "Asset is not owned by this listing. Probably was not sent to the smart contract, or was already sold."
                );
            }
        } else {
            if (
                IERC1155(listing.nftAddress).balanceOf(
                    listing.seller,
                    listing.tokenId
                ) < listing.amount
            ) {
                revert(
                "Insufficient balance of the asset in this listing. Probably was not sent to the smart contract, or was already sold."
                );
            }
        }
        if (listing.erc20Address != erc20Address) {
            revert(
            "ERC20 token address as a payer method should be the same as in the listing. Either listing, or method call has wrong ERC20 address."
            );
        }
        uint256 fee = (listing.price * _marketplaceFee) / 10000;
        listing.state = State.SOLD;
        listing.buyer = buyer;
        _listings[listingId] = listing;
        IERC20 token = IERC20(listing.erc20Address);
        if (listing.price + fee > token.allowance(buyer, address(this))) {
            if (msg.value > 0) {
                Address.sendValue(payable(msg.sender), msg.value);
            }
            revert(
            "Insufficient ERC20 allowance balance for paying for the asset."
            );
        }
        token.transferFrom(buyer, _marketplaceFeeRecipient, fee);
        token.transferFrom(buyer, listing.seller, listing.price);
        if (listing.isErc721) {
            IERC721(listing.nftAddress).safeTransferFrom(
                listing.seller,
                buyer,
                listing.tokenId,
                abi.encodePacked(
                    "CUSTOMTOKEN0x",
                    _toAsciiString(listing.erc20Address),
                    "'''###'''",
                    _uint2str(listing.price)
                )
            );
        } else {
            IERC1155(listing.nftAddress).safeTransferFrom(
                listing.seller,
                buyer,
                listing.tokenId,
                listing.amount,
                ""
            );
        }
        _toRemove(listingId);
        emit ListingSold(buyer, listingId);
    }

    /**
     * @dev Cancel listing - returns the NFT asset to the seller.
     * @param listingId - id of the listing to cancel
     */
    function cancelListing(string memory listingId) public virtual {
        Listing memory listing = _listings[listingId];
        require(
            listing.state == State.INITIATED,
            "Listing is not in INITIATED state. Aborting."
        );
        require(
            listing.seller == msg.sender || msg.sender == owner(),
            "Listing can't be cancelled from other then seller or owner. Aborting."
        );
        listing.state = State.CANCELLED;
        _listings[listingId] = listing;
        if(listing.isErc721 && listing.erc20Address == address(0)){
            uint256 cashbackSum = 0;
            if (_isTatumNFT(listing.nftAddress, listing.tokenId, listing.price)) {
                uint256[] memory cashback = Tatum(listing.nftAddress)
                .tokenCashbackValues(listing.tokenId, listing.price);
                for (uint256 j = 0; j < cashback.length; j++) {
                    cashbackSum += cashback[j];
                }
            }
            if (cashbackSum > 0) {
                Address.sendValue(payable(listing.seller), cashbackSum);
            }
        }
        _toRemove(listingId);
        emit ListingCancelled(listingId);
    }

    function _isTatumNFT(address addr, uint256 p1, uint256 p2) internal returns (bool){
        bool success;
        bytes memory data = abi.encodeWithSelector(bytes4(keccak256("tokenCashbackValues(uint256,uint256)")), p1, p2);

        assembly {
            success := call(
            gas(), // gas remaining
            addr, // destination address
            0, // no ether
            add(data, 32), // input buffer (starts after the first 32 bytes in the `data` array)
            mload(data), // input length (loaded from the first 32 bytes in the `data` array)
            0, // output buffer
            0               // output length
            )
        }

        return success;
    }

    function _isTatumNFT(address addr, uint256 p1) internal returns (bool){
        bool success;
        bytes memory data = abi.encodeWithSelector(bytes4(keccak256("getCashbackAddress(uint256)")), p1);

        assembly {
            success := call(
            gas(), // gas remaining
            addr, // destination address
            0, // no ether
            add(data, 32), // input buffer (starts after the first 32 bytes in the `data` array)
            mload(data), // input length (loaded from the first 32 bytes in the `data` array)
            0, // output buffer
            0               // output length
            )
        }

        return success;
    }
}


// File contracts/tatum/nft/NftAuction.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;
contract Tatum {
    function tokenCashbackValues(uint256 tokenId, uint256 tokenPrice)
    public
    view
    virtual
    returns (uint256[] memory)
    {}

    function getCashbackAddress(uint256 tokenId)
    public
    view
    virtual
    returns (address)
    {}
}

contract NftAuction is Ownable, Pausable {
    using Address for address;

    struct Auction {
        // address of the seller
        address seller;
        // address of the token to sale
        address nftAddress;
        // ID of the NFT
        uint256 tokenId;
        // if the auction is for ERC721 - true - or ERC1155 - false
        bool isErc721;
        // Block height of end of auction
        uint256 endedAt;
        // Block height, in which the auction started.
        uint256 startedAt;
        // optional - if the auction is settled in the ERC20 token or in native currency
        address erc20Address;
        // for ERC-1155 - how many tokens are for sale
        uint256 amount;
        // Ending price of the asset at the end of the auction
        uint256 endingPrice;
        // Actual highest bidder
        address bidder;
        // Actual highest bid fee included
        uint256 highestBid;
    }

    // List of all auctions id => auction.
    mapping(string => Auction) private _auctions;

    uint256 private _auctionCount = 0;

    string[] private _openAuctions;

    // in percents, what's the fee for the auction house, 1% - 100, 100% - 10000, range 1-10000 means 0.01% - 100%
    uint256 private _auctionFee;
    // recipient of the auction fee
    address private _auctionFeeRecipient;

    /**
     * @dev Emitted when new auction is created by the owner of the contract. Amount is valid only for ERC-1155 tokens
     */
    event AuctionCreated(
        bool indexed isErc721,
        address indexed nftAddress,
        uint256 indexed tokenId,
        string id,
        uint256 amount,
        address erc20Address,
        uint256 endedAt
    );

    /**
     * @dev Emitted when auction assets were bid.
     */
    event AuctionBid(address indexed buyer, uint256 indexed amount, string id);

    /**
     * @dev Emitted when auction is settled.
     */
    event AuctionSettled(string id);

    /**
     * @dev Emitted when auction was cancelled and assets were returned to the seller.
     */
    event AuctionCancelled(string id);

    receive() external payable {}

    function onERC1155Received(
        address,
        address,
        uint256,
        uint256,
        bytes memory
    ) public virtual returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(
        address,
        address,
        uint256[] memory,
        uint256[] memory,
        bytes memory
    ) public virtual returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }

    function onERC721Received(
        address,
        address,
        uint256,
        bytes memory
    ) public virtual returns (bytes4) {
        return this.onERC721Received.selector;
    }

    constructor(uint256 fee, address feeRecipient) {
        _auctionFee = fee;
        _auctionFeeRecipient = feeRecipient;
    }

    function getAuctionFee() public view virtual returns (uint256) {
        return _auctionFee;
    }

    function getOpenAuctions()
    public
    view
    virtual
    returns (string[] memory)
    {
        return _openAuctions;
    }

    function getAuctionFeeRecipient() public view virtual returns (address) {
        return _auctionFeeRecipient;
    }

    function getAuction(string memory id)
    public
    view
    virtual
    returns (Auction memory)
    {
        return _auctions[id];
    }

    function setAuctionFee(uint256 fee) public virtual onlyOwner {
        require(
            _auctionCount == 0,
            "Fee can't be changed if there is ongoing auction."
        );
        _auctionFee = fee;
    }

    function setAuctionFeeRecipient(address recipient)
    public
    virtual
    onlyOwner
    {
        _auctionFeeRecipient = recipient;
    }

    /**
     * Check if the seller is the owner of the token.
     * We expect that the owner of the tokens approves the spending before he launch the auction
     * The function escrows the tokens to sell
     **/
    function _escrowTokensToSell(
        bool isErc721,
        address nftAddress,
        address seller,
        uint256 tokenId,
        uint256 amount
    ) internal {
        if (!isErc721) {
            require(amount > 0);
            require(
                IERC1155(nftAddress).balanceOf(seller, tokenId) >= amount,
                "ERC1155 token balance is not sufficient for the seller.."
            );
            //    IERC1155(nftAddress).safeTransferFrom(seller,address(this),tokenId,amount,"");
        } else {
            require(
                IERC721(nftAddress).ownerOf(tokenId) == seller,
                "ERC721 token does not belong to the author."
            );
            //    IERC721(nftAddress).safeTransferFrom(seller, address(this), tokenId);
        }
    }

    /**
     * Transfer NFT from the contract to the recipient
     */
    function _transferNFT(
        bool isErc721,
        address nftAddress,
        address sender,
        address recipient,
        uint256 tokenId,
        uint256 amount,
        address erc20Address
    ) internal {
        if (!isErc721) {
            IERC1155(nftAddress).safeTransferFrom(
                sender,
                recipient,
                tokenId,
                amount,
                ""
            );
        } else {
            uint256 cashbackSum = 0;
            if (_isTatumNFT(nftAddress, tokenId)) {
                if (Tatum(nftAddress).getCashbackAddress(tokenId) == address(0)) {
                    uint256[] memory cashback = Tatum(nftAddress)
                    .tokenCashbackValues(tokenId, amount);
                    for (uint256 j = 0; j < cashback.length; j++) {
                        cashbackSum += cashback[j];
                    }
                }
            }
            if (erc20Address == address(0)) {
                IERC721(nftAddress).safeTransferFrom{value : cashbackSum}(
                    sender,
                    recipient,
                    tokenId,
                    abi.encodePacked(
                        "SAFETRANSFERFROM",
                        "'''###'''",
                        _uint2str(amount)
                    )
                );
            } else {
                bytes memory bytesInput = abi.encodePacked(
                    "CUSTOMTOKEN0x",
                    _toAsciiString(erc20Address),
                    "'''###'''",
                    _uint2str(amount)
                );
                IERC721(nftAddress).safeTransferFrom{value : cashbackSum}(
                    sender,
                    recipient,
                    tokenId,
                    bytesInput
                );
            }
        }
    }

    function _toAsciiString(address x) internal pure returns (bytes memory) {
        bytes memory s = new bytes(40);
        for (uint256 i = 0; i < 20; i++) {
            bytes1 b = bytes1(uint8(uint256(uint160(x)) / (2 ** (8 * (19 - i)))));
            bytes1 hi = bytes1(uint8(b) / 16);
            bytes1 lo = bytes1(uint8(b) - 16 * uint8(hi));
            s[2 * i] = _char(hi);
            s[2 * i + 1] = _char(lo);
        }
        return s;
    }

    function _char(bytes1 b) internal pure returns (bytes1 c) {
        if (uint8(b) < 10) return bytes1(uint8(b) + 0x30);
        else return bytes1(uint8(b) + 0x57);
    }

    /**
     * Transfer assets locked in the highest bid to the recipient
     * @param erc20Address - if we are working with ERC20 token or native asset
     * @param amount - bid value to be distributed
     * @param recipient - where we will send the bid
     * @param settleOrReturnFee - when true, fee is send to the auction recipient, otherwise returned to the owner
     */
    function _transferAssets(
        address erc20Address,
        uint256 amount,
        address recipient,
        bool settleOrReturnFee
    ) internal {
        uint256 fee = (amount * _auctionFee) / 10000;
        if (erc20Address != address(0)) {
            if (settleOrReturnFee) {
                IERC20(erc20Address).transfer(recipient, amount - fee);
                IERC20(erc20Address).transfer(_auctionFeeRecipient, fee);
            } else {
                IERC20(erc20Address).transfer(recipient, amount);
            }
        } else {
            if (settleOrReturnFee) {
                Address.sendValue(payable(recipient), amount - fee);
                Address.sendValue(payable(_auctionFeeRecipient), fee);
            } else {
                Address.sendValue(payable(recipient), amount);
            }
        }
    }

    /**
     * @dev Create new auction of the NFT token in the marketplace.
     * @param id - ID of the auction, must be unique
     * @param isErc721 - whether the auction is for ERC721 or ERC1155 token
     * @param nftAddress - address of the NFT token
     * @param tokenId - ID of the NFT token
     * @param amount - ERC1155 only, number of tokens to sold.
     * @param erc20Address - address of the ERC20 token, which will be used for the payment. If native asset is used, this should be 0x0 address
     */
    function createAuction(
        string memory id,
        bool isErc721,
        address nftAddress,
        uint256 tokenId,
        address seller,
        uint256 amount,
        uint256 endedAt,
        address erc20Address
    ) public whenNotPaused {
        require(
            _auctions[id].startedAt == 0,
            "Auction already existed for current auction Id"
        );
        require(
            endedAt > block.number + 5,
            "Auction must last at least 5 blocks from this block"
        );
        // check if the seller owns the tokens he wants to put on auction
        // transfer the tokens to the auction house
        _escrowTokensToSell(isErc721, nftAddress, seller, tokenId, amount);

        _auctionCount++;
        Auction memory auction = Auction(
            seller,
            nftAddress,
            tokenId,
            isErc721,
            endedAt,
            block.number,
            erc20Address,
            amount,
            0,
            address(0),
            0
        );
        _auctions[id] = auction;
        _openAuctions.push(id);
        emit AuctionCreated(
            isErc721,
            nftAddress,
            tokenId,
            id,
            amount,
            erc20Address,
            endedAt
        );
    }

    /**
     * @dev Buyer wants to buy NFT from auction. All the required checks must pass.
     * Buyer must approve spending of ERC20 tokens, which will be deducted from his account to the auction contract.
     * Contract must detect, if the bidder bid higher value thank the actual highest bid. If it's not enough, bid is not valid.
     * If bid is the highest one, previous bidders assets will be released back to him - we are aware of reentrancy attacks, but we will cover that.
     * Bid must be processed only during the validity of the auction, otherwise it's not accepted.
     * @param id - id of the auction to buy
     * @param bidValue - bid value + the auction fee
     * @param bidder - bidder of the auction, from which account the ERC20 assets will be debited
     */
    function bidForExternalBidder(
        string memory id,
        uint256 bidValue,
        address bidder
    ) public whenNotPaused {
        Auction memory auction = _auctions[id];
        require(
            auction.erc20Address != address(0),
            "Auction must be placed for ERC20 token."
        );
        require(
            auction.endedAt > block.number,
            "Auction has already ended. Unable to process bid. Aborting."
        );
        uint256 bidWithoutFee = (bidValue / (10000 + _auctionFee)) * 10000;
        require(
            auction.endingPrice < bidWithoutFee,
            "Bid fee of the auction fee is lower than actual highest bid price. Aborting."
        );
        require(
            IERC20(auction.erc20Address).allowance(bidder, address(this)) >=
            bidValue,
            "Insufficient approval for ERC20 token for the auction bid. Aborting."
        );

        Auction memory newAuction = Auction(
            auction.seller,
            auction.nftAddress,
            auction.tokenId,
            auction.isErc721,
            auction.endedAt,
            block.number,
            auction.erc20Address,
            auction.amount,
            auction.endingPrice,
            auction.bidder,
            auction.highestBid
        );
        // reentrancy attack - we delete the auction temporarily
        delete _auctions[id];

        IERC20 token = IERC20(newAuction.erc20Address);
        if (!token.transferFrom(bidder, address(this), bidValue)) {
            revert(
            "Unable to transfer ERC20 tokens from the bidder to the Auction. Aborting"
            );
        }

        // returns the previous bid to the bidder
        if (newAuction.bidder != address(0) && newAuction.highestBid != 0) {
            _transferAssets(
                newAuction.erc20Address,
                newAuction.highestBid,
                newAuction.bidder,
                false
            );
        }

        // paid amount is on the Auction SC, we just need to update the auction status
        newAuction.endingPrice = bidWithoutFee;
        newAuction.highestBid = bidValue;
        newAuction.bidder = bidder;

        _auctions[id] = newAuction;
        emit AuctionBid(bidder, bidValue, id);
    }

    /**
     * @dev Buyer wants to buy NFT from auction. All the required checks must pass.
     * Buyer must either send ETH with this endpoint, or ERC20 tokens will be deducted from his account to the auction contract.
     * Contract must detect, if the bidder bid higher value thank the actual highest bid. If it's not enough, bid is not valid.
     * If bid is the highest one, previous bidders assets will be released back to him - we are aware of reentrancy attacks, but we will cover that.
     * Bid must be processed only during the validity of the auction, otherwise it's not accepted.
     * @param id - id of the auction to buy
     * @param bidValue - bid value + the auction fee
     */
    function bid(string memory id, uint256 bidValue)
    public
    payable
    whenNotPaused
    {
        Auction memory auction = _auctions[id];
        uint256 bidWithoutFee = (bidValue / (10000 + _auctionFee)) * 10000;
        require(
            auction.endedAt > block.number,
            "Auction has already ended. Unable to process bid. Aborting."
        );
        require(
            auction.endingPrice < bidWithoutFee,
            "Bid fee of the auction fee is lower than actual highest bid price. Aborting."
        );
        if (auction.erc20Address == address(0)) {
            require(
                bidValue <= msg.value,
                "Wrong amount entered for the bid. Aborting."
            );
        }
        if (auction.erc20Address != address(0)) {
            require(
                IERC20(auction.erc20Address).allowance(
                    msg.sender,
                    address(this)
                ) >= bidValue,
                "Insufficient approval for ERC20 token for the auction bid. Aborting."
            );
        }

        Auction memory newAuction = Auction(
            auction.seller,
            auction.nftAddress,
            auction.tokenId,
            auction.isErc721,
            auction.endedAt,
            block.number,
            auction.erc20Address,
            auction.amount,
            auction.endingPrice,
            auction.bidder,
            auction.highestBid
        );
        // reentrancy attack - we delete the auction temporarily
        delete _auctions[id];

        uint256 cashbackSum = 0;
        if (newAuction.isErc721) {
            if (_isTatumNFT(newAuction.nftAddress, newAuction.tokenId)) {
                if (
                    Tatum(newAuction.nftAddress).getCashbackAddress(
                        newAuction.tokenId
                    ) == address(0)
                ) {
                    uint256[] memory cashback = Tatum(newAuction.nftAddress)
                    .tokenCashbackValues(newAuction.tokenId, bidValue);
                    for (uint256 j = 0; j < cashback.length; j++) {
                        cashbackSum += cashback[j];
                    }
                    if (newAuction.erc20Address == address(0)) {
                        require(msg.value >= cashbackSum + bidValue, "Balance Insufficient to pay royalties");
                    } else {
                        require(msg.value >= cashbackSum, "Balance Insufficient to pay royalties");
                    }
                    Address.sendValue(payable(address(this)), cashbackSum);
                }
            }
        }
        if (newAuction.erc20Address != address(0)) {
            IERC20 token = IERC20(newAuction.erc20Address);
            if (!token.transferFrom(msg.sender, address(this), bidValue)) {
                revert(
                "Unable to transfer ERC20 tokens to the Auction. Aborting"
                );
            }
        } else {
            Address.sendValue(payable(address(this)), bidValue);
        }
        // returns the previous bid to the bidder
        if (newAuction.bidder != address(0) && newAuction.highestBid != 0) {
            _transferAssets(
                newAuction.erc20Address,
                newAuction.highestBid,
                newAuction.bidder,
                false
            );
        }
        if (msg.value > bidValue + cashbackSum) {
            Address.sendValue(
                payable(msg.sender),
                msg.value - cashbackSum - bidValue
            );
        }
        // paid amount is on the Auction SC, we just need to update the auction status
        newAuction.endingPrice = bidWithoutFee;
        newAuction.highestBid = bidValue;
        newAuction.bidder = msg.sender;

        _auctions[id] = newAuction;
        emit AuctionBid(msg.sender, bidValue, id);
    }

    /**
     * Settle the already ended auction -
     */
    function settleAuction(string memory id) public payable virtual {
        // fee must be sent to the fee recipient
        // NFT token to the bidder
        // payout to the seller
        Auction memory auction = _auctions[id];
        require(
            auction.endedAt < block.number,
            "Auction can't be settled before it reaches the end."
        );

        bool isErc721 = auction.isErc721;
        address nftAddress = auction.nftAddress;
        uint256 amount = auction.amount;
        uint256 tokenId = auction.tokenId;
        address erc20Address = auction.erc20Address;
        uint256 highestBid = auction.highestBid;
        address bidder = auction.bidder;

        // avoid reentrancy attacks
        delete _auctions[id];

        _transferNFT(
            isErc721,
            nftAddress,
            auction.seller,
            bidder,
            tokenId,
            amount,
            auction.erc20Address
        );
        _transferAssets(erc20Address, highestBid, auction.seller, true);
        _toRemove(id);
        _auctionCount--;
        emit AuctionSettled(id);
    }

    function _toRemove(string memory id) internal {
        for (uint x = 0; x < _openAuctions.length; x++) {
            if (
                keccak256(abi.encodePacked(_openAuctions[x])) ==
                keccak256(abi.encodePacked(id))
            ) {
                for (uint i = x; i < _openAuctions.length - 1; i++) {
                    _openAuctions[i] = _openAuctions[i + 1];
                }
                _openAuctions.pop();
            }
        }
    }
    /**
     * @dev Cancel auction - returns the NFT asset to the seller.
     * @param id - id of the auction to cancel
     */
    function cancelAuction(string memory id) public payable virtual {
        Auction memory auction = _auctions[id];
        require(
            auction.seller != address(0),
            "Auction is already settled. Aborting."
        );
        require(
            auction.seller == msg.sender || msg.sender == owner(),
            "Auction can't be cancelled from other thank seller or owner. Aborting."
        );
        // bool isErc721 = auction.isErc721;
        // address nftAddress = auction.nftAddress;
        // uint256 amount = auction.amount;
        // uint256 tokenId = auction.tokenId;
        address erc20Address = auction.erc20Address;
        uint256 highestBid = auction.highestBid;
        address bidder = auction.bidder;

        // prevent reentrancy attack
        delete _auctions[id];

        // we have assured that the reentrancy attack wont happen because we have deleted the auction from the list of auctions before we are sending the assets back
        // returns the NFT to the seller

        // returns the highest bid to the bidder
        if (bidder != address(0) && highestBid != 0) {
            _transferAssets(erc20Address, highestBid, bidder, false);
        }
        uint256 cashbackSum = 0;
        if (_isTatumNFT(auction.nftAddress, auction.tokenId)) {
            if (
                Tatum(auction.nftAddress).getCashbackAddress(auction.tokenId) ==
                address(0)
            ) {
                uint256[] memory cashback = Tatum(auction.nftAddress)
                .tokenCashbackValues(auction.tokenId, highestBid);
                for (uint256 j = 0; j < cashback.length; j++) {
                    cashbackSum += cashback[j];
                }
            }
        }
        if (cashbackSum > 0 && bidder != address(0)) {
            Address.sendValue(payable(bidder), cashbackSum);
        }
        _auctionCount--;
        _toRemove(id);
        emit AuctionCancelled(id);
    }

    function _uint2str(uint256 _i)
    internal
    pure
    returns (string memory _uintAsString)
    {
        if (_i == 0) {
            return "0";
        }
        uint256 j = _i;
        uint256 len;
        while (j != 0) {
            len++;
            j /= 10;
        }
        bytes memory bstr = new bytes(len);
        uint256 k = len;
        while (_i != 0) {
            k = k - 1;
            uint8 temp = (48 + uint8(_i - (_i / 10) * 10));
            bytes1 b1 = bytes1(temp);
            bstr[k] = b1;
            _i /= 10;
        }
        return string(bstr);
    }

    function _isTatumNFT(address addr, uint256 p1) internal returns (bool){
        bool success;
        bytes memory data = abi.encodeWithSelector(bytes4(keccak256("getCashbackAddress(uint256)")), p1);

        assembly {
            success := call(
            gas(), // gas remaining
            addr, // destination address
            0, // no ether
            add(data, 32), // input buffer (starts after the first 32 bytes in the `data` array)
            mload(data), // input length (loaded from the first 32 bytes in the `data` array)
            0, // output buffer
            0               // output length
            )
        }

        return success;
    }
}


// File contracts/token/ERC1155/presets/ERC1155PresetMinterPauser.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev {ERC1155} token, including:
 *
 *  - ability for holders to burn (destroy) their tokens
 *  - a minter role that allows for token minting (creation)
 *  - a pauser role that allows to stop all token transfers
 *
 * This contract uses {AccessControl} to lock permissioned functions using the
 * different roles - head to its documentation for details.
 *
 * The account that deploys the contract will be granted the minter and pauser
 * roles, as well as the default admin role, which will let it grant both minter
 * and pauser roles to other accounts.
 */
contract ERC1155PresetMinterPauser is Context, AccessControlEnumerable, ERC1155Burnable, ERC1155Pausable {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /**
     * @dev Grants `DEFAULT_ADMIN_ROLE`, `MINTER_ROLE`, and `PAUSER_ROLE` to the account that
     * deploys the contract.
     */
    constructor(string memory uri) ERC1155(uri) {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        _setupRole(MINTER_ROLE, _msgSender());
        _setupRole(PAUSER_ROLE, _msgSender());
    }

    /**
     * @dev Creates `amount` new tokens for `to`, of token type `id`.
     *
     * See {ERC1155-_mint}.
     *
     * Requirements:
     *
     * - the caller must have the `MINTER_ROLE`.
     */
    function mint(address to, uint256 id, uint256 amount, bytes memory data) public virtual {
        require(hasRole(MINTER_ROLE, _msgSender()), "ERC1155PresetMinterPauser: must have minter role to mint");

        _mint(to, id, amount, data);
    }

    /**
     * @dev xref:ROOT:erc1155.adoc#batch-operations[Batched] variant of {mint}.
     */
    function mintBatch(address to, uint256[] memory ids, uint256[] memory amounts, bytes memory data) public virtual {
        require(hasRole(MINTER_ROLE, _msgSender()), "ERC1155PresetMinterPauser: must have minter role to mint");

        _mintBatch(to, ids, amounts, data);
    }

    /**
     * @dev Pauses all token transfers.
     *
     * See {ERC1155Pausable} and {Pausable-_pause}.
     *
     * Requirements:
     *
     * - the caller must have the `PAUSER_ROLE`.
     */
    function pause() public virtual {
        require(hasRole(PAUSER_ROLE, _msgSender()), "ERC1155PresetMinterPauser: must have pauser role to pause");
        _pause();
    }

    /**
     * @dev Unpauses all token transfers.
     *
     * See {ERC1155Pausable} and {Pausable-_unpause}.
     *
     * Requirements:
     *
     * - the caller must have the `PAUSER_ROLE`.
     */
    function unpause() public virtual {
        require(hasRole(PAUSER_ROLE, _msgSender()), "ERC1155PresetMinterPauser: must have pauser role to unpause");
        _unpause();
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlEnumerable, ERC1155) returns (bool) {
        return super.supportsInterface(interfaceId);
    }

    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
        internal virtual override(ERC1155, ERC1155Pausable)
    {
        super._beforeTokenTransfer(operator, from, to, ids, amounts, data);
    }
}


// File contracts/tatum/Tatum1155.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Tatum1155 is ERC1155PresetMinterPauser {
    bool _publicMint;
    constructor(string memory uri, bool publicMint) ERC1155PresetMinterPauser(uri) {
        _publicMint=publicMint;
    }

    function safeTransfer(
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    )
    public
    virtual
    {
        return safeTransferFrom(_msgSender(), to, id, amount, data);
    }

    function safeBatchTransfer(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    )
    public
    virtual
    {
        return safeBatchTransferFrom(_msgSender(), to, ids, amounts, data);
    }

    function mintBatch(address[] memory to, uint256[][] memory ids, uint256[][] memory amounts, bytes memory data) public virtual {
        if(!_publicMint){
            require(hasRole(MINTER_ROLE, _msgSender()), "ERC1155PresetMinterPauser: must have minter role to mint");
        }
        for (uint i = 0; i < to.length; i++) {
            _mintBatch(to[i], ids[i], amounts[i], data);
        }
    }
    function mint(address to, uint256 id, uint256 amount, bytes memory data) public virtual override{
        if(!_publicMint){
            require(hasRole(MINTER_ROLE, _msgSender()), "ERC1155PresetMinterPauser: must have minter role to mint");
        }
        _mint(to, id, amount, data);
    }
    function mintBatch(address to, uint256[] memory ids, uint256[] memory amounts, bytes memory data) public virtual override {
        if(!_publicMint){
            require(hasRole(MINTER_ROLE, _msgSender()), "ERC1155PresetMinterPauser: must have minter role to mint");
        }
        _mintBatch(to, ids, amounts, data);
    }

}


// File contracts/utils/introspection/ERC2981.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
interface IERC2981 {
    /// @notice Called with the sale price to determine how much royalty
    //          is owed and to whom.
    /// @param _tokenId - the NFT asset queried for royalty information
    /// @param _value - the sale price of the NFT asset specified by _tokenId
    /// @return _receiver - address of who should be sent the royalty payment
    /// @return _royaltyAmount - the royalty payment amount for value sale price
    function royaltyInfo(uint256 _tokenId, uint256 _value)
        external
        view
        returns (address _receiver, uint256 _royaltyAmount);
}
abstract contract ERC2981 is ERC165, IERC2981 {
    /// @inheritdoc	ERC165
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override
        returns (bool)
    {
        return
            interfaceId == type(IERC2981).interfaceId ||
            super.supportsInterface(interfaceId);
    }
}


// File contracts/tatum/Tatum721Cashback.sol

//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;
contract Tatum721Cashback is
ERC721Enumerable,
ERC721URIStorage,
ERC2981,
AccessControlEnumerable
{
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    // mapping cashback to addresses and their values
    mapping(uint256 => address[]) private _cashbackRecipients;
    mapping(uint256 => uint256[]) private _cashbackValues;
    mapping(uint256 => address) private _customToken;
    bool _publicMint;
    constructor(string memory name_, string memory symbol_,bool publicMint)
        ERC721(name_, symbol_)
    {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(MINTER_ROLE, _msgSender());
        _publicMint=publicMint;
    }

    /**
     * @dev Function to mint tokens.
     * @param to The address that will receive the minted tokens.
     * @param tokenId The token id to mint.
     * @param uri The token URI of the minted token.
     * @return A boolean that indicates if the operation was successful.
     */
    function mintWithTokenURI(
        address to,
        uint256 tokenId,
        string memory uri
    ) public returns (bool) {
        if(!_publicMint){
            require(
                hasRole(MINTER_ROLE, _msgSender()),
                "ERC721PresetMinterPauserAutoId: must have minter role to mint"
            );
        }
        _mint(to, tokenId);
        _setTokenURI(tokenId, uri);
        return true;
    }
    function royaltyInfo(uint256 tokenId, uint256 value)
            external
            view
            override
            returns (address, uint256)
        {
            require(value >= 1, "value should be greater than or equal to 1");
            return (_cashbackRecipients[tokenId][0], _cashbackValues[tokenId][0]);
        }
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControlEnumerable, ERC721, ERC721Enumerable, ERC2981)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function tokenURI(uint256 tokenId)
        public
        view
        virtual
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return ERC721URIStorage.tokenURI(tokenId);
    }

    function tokenCashbackValues(uint256 tokenId, uint256 tokenPrice)
        public
        view
        virtual
        returns (uint256[] memory)
    {
        return _cashbackValues[tokenId];
    }

    function tokenCashbackRecipients(uint256 tokenId)
        public
        view
        virtual
        returns (address[] memory)
    {
        return _cashbackRecipients[tokenId];
    }

    function allowance(address a, uint256 t) public view returns (bool) {
        return _isApprovedOrOwner(a, t);
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual override(ERC721, ERC721Enumerable) {
        super._beforeTokenTransfer(from, to, tokenId);
    }

    function _burn(uint256 tokenId)
        internal
        virtual
        override(ERC721, ERC721URIStorage)
    {
        return ERC721URIStorage._burn(tokenId);
    }

    function mintMultiple(
        address[] memory to,
        uint256[] memory tokenId,
        string[] memory uri
    ) public returns (bool) {
        if(!_publicMint){
            require(
                hasRole(MINTER_ROLE, _msgSender()),
                "ERC721PresetMinterPauserAutoId: must have minter role to mint"
            );
        }
        for (uint256 i = 0; i < to.length; i++) {
            _mint(to[i], tokenId[i]);
            _setTokenURI(tokenId[i], uri[i]);
        }
        return true;
    }

    function updateCashbackForAuthor(uint256 tokenId, uint256 cashbackValue)
        public
        returns (bool)
    {
        for (uint256 i = 0; i < _cashbackValues[tokenId].length; i++) {
            if (_cashbackRecipients[tokenId][i] == _msgSender()) {
                _cashbackValues[tokenId][i] = cashbackValue;
                return true;
            }
        }
        return true;
    }

    function getCashbackAddress(uint256 tokenId)
        public
        view
        virtual
        returns (address)
    {
        return _customToken[tokenId];
    }

    function mintMultipleCashback(
        address[] memory to,
        uint256[] memory tokenId,
        string[] memory uri,
        address[][] memory recipientAddresses,
        uint256[][] memory cashbackValues,
        address erc20
    ) public returns (bool) {
        require(
            erc20 != address(0),
            "Custom cashbacks cannot be set to 0 address"
        );
        for (uint256 i = 0; i < tokenId.length; i++) {
            _customToken[tokenId[i]] = erc20;
        }
        return
            mintMultipleCashback(
                to,
                tokenId,
                uri,
                recipientAddresses,
                cashbackValues
            );
    }

    function mintMultipleCashback(
        address[] memory to,
        uint256[] memory tokenId,
        string[] memory uri,
        address[][] memory recipientAddresses,
        uint256[][] memory cashbackValues
    ) public returns (bool) {
        if(!_publicMint){
            require(
                hasRole(MINTER_ROLE, _msgSender()),
                "ERC721PresetMinterPauserAutoId: must have minter role to mint"
            );
        }
        for (uint256 i = 0; i < to.length; i++) {
            _mint(to[i], tokenId[i]);
            _setTokenURI(tokenId[i], uri[i]);
            _cashbackRecipients[tokenId[i]] = recipientAddresses[i];
            _cashbackValues[tokenId[i]] = cashbackValues[i];
        }
        return true;
    }

    function mintWithCashback(
        address to,
        uint256 tokenId,
        string memory uri,
        address[] memory recipientAddresses,
        uint256[] memory cashbackValues,
        address erc20
    ) public returns (bool) {
        require(
            erc20 != address(0),
            "Custom cashbacks cannot be set to 0 address"
        );
        _customToken[tokenId] = erc20;
        return
            mintWithCashback(
                to,
                tokenId,
                uri,
                recipientAddresses,
                cashbackValues
            );
    }

    function mintWithCashback(
        address to,
        uint256 tokenId,
        string memory uri,
        address[] memory recipientAddresses,
        uint256[] memory cashbackValues
    ) public returns (bool) {
        if(!_publicMint){
            require(
                hasRole(MINTER_ROLE, _msgSender()),
                "ERC721PresetMinterPauserAutoId: must have minter role to mint"
            );
        }
        _mint(to, tokenId);
        _setTokenURI(tokenId, uri);
        // saving cashback addresses and values
        _cashbackRecipients[tokenId] = recipientAddresses;
        _cashbackValues[tokenId] = cashbackValues;
        return true;
    }

    function burn(uint256 tokenId) public virtual {
        //solhint-disable-next-line max-line-length
        require(
            _isApprovedOrOwner(_msgSender(), tokenId),
            "ERC721Burnable: caller is not owner nor approved"
        );
        _burn(tokenId);
    }

    function safeTransfer(address to, uint256 tokenId) public payable {
        address erc = _customToken[tokenId];
        IERC20 token;
        if (erc != address(0)) {
            token = IERC20(erc);
        }
        if (_cashbackRecipients[tokenId].length != 0) {
            // checking cashback addresses exists and sum of cashbacks
            require(
                _cashbackRecipients[tokenId].length != 0,
                "CashbackToken should be of cashback type"
            );
            uint256 sum = 0;
            for (uint256 i = 0; i < _cashbackValues[tokenId].length; i++) {
                sum += _cashbackValues[tokenId][i];
            }
            if (erc == address(0)) {
                if (sum > msg.value) {
                    payable(msg.sender).transfer(msg.value);
                    revert(
                        "Value should be greater than or equal to cashback value"
                    );
                }
                for (
                    uint256 i = 0;
                    i < _cashbackRecipients[tokenId].length;
                    i++
                ) {
                    // transferring cashback to authors
                    if (_cashbackValues[tokenId][i] > 0) {
                        payable(_cashbackRecipients[tokenId][i]).transfer(
                            _cashbackValues[tokenId][i]
                        );
                    }
                }
                if (msg.value > sum) {
                    payable(msg.sender).transfer(msg.value - sum);
                }
            } else {
                if (sum > token.allowance(_msgSender(), address(this))) {
                    revert(
                        "Insufficient ERC20 allowance balance for paying for the asset."
                    );
                }
                for (
                    uint256 i = 0;
                    i < _cashbackRecipients[tokenId].length;
                    i++
                ) {
                    // transferring cashback to authors
                    if (_cashbackValues[tokenId][i] > 0) {
                        token.transferFrom(
                            _msgSender(),
                            to,
                            _cashbackValues[tokenId][i]
                        );
                    }
                }
                if (msg.value > 0) {
                    payable(_msgSender()).transfer(msg.value);
                }
            }
            _safeTransfer(_msgSender(), to, tokenId, "");
        } else {
            if (msg.value > 0) {
                payable(msg.sender).transfer(msg.value);
            }
            _safeTransfer(_msgSender(), to, tokenId, "");
        }
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes memory bytesData
    ) public payable virtual override {
        address erc = _customToken[tokenId];
        IERC20 token;
        if (erc != address(0)) {
            token = IERC20(erc);
        }
        if (_cashbackRecipients[tokenId].length != 0) {
            // checking cashback addresses exists and sum of cashbacks
            require(
                _cashbackRecipients[tokenId].length != 0,
                "CashbackToken should be of cashback type"
            );
            uint256 sum = 0;
            for (uint256 i = 0; i < _cashbackValues[tokenId].length; i++) {
                sum += _cashbackValues[tokenId][i];
            }
            if (erc == address(0)) {
                if (sum > msg.value) {
                    payable(from).transfer(msg.value);
                    revert(
                        "Value should be greater than or equal to cashback value"
                    );
                }
                for (
                    uint256 i = 0;
                    i < _cashbackRecipients[tokenId].length;
                    i++
                ) {
                    // transferring cashback to authors
                    if (_cashbackValues[tokenId][i] > 0) {
                        payable(_cashbackRecipients[tokenId][i]).transfer(
                            _cashbackValues[tokenId][i]
                        );
                    }
                }
                if (msg.value > sum) {
                    payable(from).transfer(msg.value - sum);
                }
            } else {
                if (sum > token.allowance(to, address(this))) {
                    revert(
                        "Insufficient ERC20 allowance balance for paying for the asset."
                    );
                }
                for (
                    uint256 i = 0;
                    i < _cashbackRecipients[tokenId].length;
                    i++
                ) {
                    // transferring cashback to authors
                    if (_cashbackValues[tokenId][i] > 0) {
                        token.transferFrom(
                            to,
                            _cashbackRecipients[tokenId][i],
                            _cashbackValues[tokenId][i]
                        );
                    }
                }
                if (msg.value > 0) {
                    payable(msg.sender).transfer(msg.value);
                }
            }
            _safeTransfer(from, to, tokenId, bytesData);
        } else {
            if (msg.value > 0) {
                payable(from).transfer(msg.value);
            }
            _safeTransfer(from, to, tokenId, bytesData);
        }
    }
}


// File contracts/tatum/Tatum721Provenance.sol

//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;
contract Tatum721Provenance is
    ERC721Enumerable,
    ERC2981,
    ERC721URIStorage,
    AccessControlEnumerable
{
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    mapping(uint256 => string[]) private _tokenData;
    mapping(uint256 => address[]) private _cashbackRecipients;
    mapping(uint256 => uint256[]) private _cashbackValues;
    mapping(uint256 => uint256[]) private _fixedValues;
    mapping(uint256 => address) private _customToken;
    bool _publicMint;
    event TransferWithProvenance(
        uint256 indexed id,
        address owner,
        string data,
        uint256 value
    );

    constructor(string memory name_, string memory symbol_, bool publicMint)
        ERC721(name_, symbol_)
    {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(MINTER_ROLE, _msgSender());
        _publicMint=publicMint;
    }
    function royaltyInfo(uint256 tokenId, uint256 value)
        external
        view
        override
        returns (address, uint256)
    {
        uint256 result;
        uint256 cbvalue = (_cashbackValues[tokenId][0] * value) / 10000;
        result=_cashbackCalculator(cbvalue,_fixedValues[tokenId][0]);
        return (_cashbackRecipients[tokenId][0],result);
    }
    function _appendTokenData(uint256 tokenId, string calldata tokenData)
        internal
        virtual
    {
        require(
            _exists(tokenId),
            "ERC721URIStorage: URI set of nonexistent token"
        );
        _tokenData[tokenId].push(tokenData);
    }

    function mintWithTokenURI(
        address to,
        uint256 tokenId,
        string memory uri,
        address[] memory recipientAddresses,
        uint256[] memory cashbackValues,
        uint256[] memory fValues,
        address erc20
    ) public {
        require(
            erc20 != address(0),
            "Custom cashbacks cannot be set to 0 address"
        );
        _customToken[tokenId] = erc20;
        return
            mintWithTokenURI(
                to,
                tokenId,
                uri,
                recipientAddresses,
                cashbackValues,
                fValues
            );
    }

    function mintWithTokenURI(
        address to,
        uint256 tokenId,
        string memory uri,
        address[] memory recipientAddresses,
        uint256[] memory cashbackValues,
        uint256[] memory fValues
    ) public {
        if(!_publicMint){
            require(
                hasRole(MINTER_ROLE, _msgSender()),
                "ERC721PresetMinterPauserAutoId: must have minter role to mint"
            );
        }
        _mint(to, tokenId);
        _setTokenURI(tokenId, uri);
        // saving cashback addresses and values
        if (recipientAddresses.length > 0) {
            _cashbackRecipients[tokenId] = recipientAddresses;
            _cashbackValues[tokenId] = cashbackValues;
            _fixedValues[tokenId] = fValues;
        }
    }

    function mintMultiple(
        address[] memory to,
        uint256[] memory tokenId,
        string[] memory uri,
        address[][] memory recipientAddresses,
        uint256[][] memory cashbackValues,
        uint256[][] memory fValues,
        address erc20
    ) public {
        require(
            erc20 != address(0),
            "Custom cashbacks cannot be set to 0 address"
        );
        for (uint256 i; i < to.length; i++) {
            _customToken[tokenId[i]] = erc20;
        }
        return
            mintMultiple(
                to,
                tokenId,
                uri,
                recipientAddresses,
                cashbackValues,
                fValues
            );
    }

    function mintMultiple(
        address[] memory to,
        uint256[] memory tokenId,
        string[] memory uri,
        address[][] memory recipientAddresses,
        uint256[][] memory cashbackValues,
        uint256[][] memory fValues
    ) public {
        if(!_publicMint){
            require(
                hasRole(MINTER_ROLE, _msgSender()),
                "ERC721PresetMinterPauserAutoId: must have minter role to mint"
            );
        }
        for (uint256 i; i < to.length; i++) {
            _mint(to[i], tokenId[i]);
            _setTokenURI(tokenId[i], uri[i]);
            if (
                recipientAddresses.length > 0 &&
                recipientAddresses[i].length > 0
            ) {
                _cashbackRecipients[tokenId[i]] = recipientAddresses[i];
                _cashbackValues[tokenId[i]] = cashbackValues[i];
                _fixedValues[tokenId[i]] = fValues[i];
            }
        }
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControlEnumerable, ERC721, ERC721Enumerable, ERC2981)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function tokenURI(uint256 tokenId)
        public
        view
        virtual
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return ERC721URIStorage.tokenURI(tokenId);
    }

    function getCashbackAddress(uint256 tokenId)
        public
        view
        virtual
        returns (address)
    {
        return _customToken[tokenId];
    }

    function getTokenData(uint256 tokenId)
        public
        view
        virtual
        returns (string[] memory)
    {
        return _tokenData[tokenId];
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual override(ERC721, ERC721Enumerable) {
        super._beforeTokenTransfer(from, to, tokenId);
    }

    function _burn(uint256 tokenId)
        internal
        virtual
        override(ERC721, ERC721URIStorage)
    {
        return ERC721URIStorage._burn(tokenId);
    }

    function tokenCashbackValues(uint256 tokenId, uint256 tokenPrice)
        public
        view
        virtual
        returns (uint256[] memory)
    {
        uint256[] memory result=_cashbackValues[tokenId];
        for(uint i=0;i<result.length;i++){
            uint256 cbvalue = (result[i] * tokenPrice) / 10000;
            result[i]=_cashbackCalculator(cbvalue,_fixedValues[tokenId][i]);
        }
        return result;
    }

    function tokenCashbackRecipients(uint256 tokenId)
        public
        view
        virtual
        returns (address[] memory)
    {
        return _cashbackRecipients[tokenId];
    }

    function updateCashbackForAuthor(uint256 tokenId, uint256 cashbackValue)
        public
    {
        for (uint256 i; i < _cashbackValues[tokenId].length; i++) {
            if (_cashbackRecipients[tokenId][i] == _msgSender()) {
                _cashbackValues[tokenId][i] = cashbackValue;
            }
        }
    }

    function burn(uint256 tokenId) public virtual {
        //solhint-disable-next-line max-line-length
        require(
            _isApprovedOrOwner(_msgSender(), tokenId),
            "ERC721Burnable: caller is not owner nor approved"
        );
        _burn(tokenId);
    }

    function _stringToUint(string memory s)
        internal
        pure
        returns (uint256 result)
    {
        bytes memory b = bytes(s);
        // result = 0;
        for (uint256 i; i < b.length; i++) {
            uint256 c = uint256(uint8(b[i]));
            if (c >= 48 && c <= 57) {
                result = result * 10 + (c - 48);
            }
        }
    }

    function allowance(address a, uint256 t) public view returns (bool) {
        return _isApprovedOrOwner(a, t);
    }

    function safeTransfer(
        address to,
        uint256 tokenId,
        bytes calldata dataBytes
    ) public payable {
        uint256 index;
        uint256 value;
        uint256 percentSum;
        IERC20 token;
        (index, value) = _bytesCheck(dataBytes);
        if (_customToken[tokenId] != address(0)) {
            token = IERC20(_customToken[tokenId]);
        }
        if (_cashbackRecipients[tokenId].length > 0) {
            for (uint256 i = 0; i < _cashbackValues[tokenId].length; i++) {
                uint256 iPercent = (_cashbackValues[tokenId][i] * value) /
                    10000;
                if (iPercent >= _fixedValues[tokenId][i]) {
                    percentSum += iPercent;
                } else {
                    percentSum += _fixedValues[tokenId][i];
                }
            }
            if (_customToken[tokenId] == address(0)) {
                if (percentSum > msg.value) {
                    payable(msg.sender).transfer(msg.value);
                    revert(
                        "Value should be greater than or equal to cashback value"
                    );
                }
            } else {
                if (percentSum > token.allowance(to, address(this))) {
                    revert(
                        "Insufficient ERC20 allowance balance for paying for the asset."
                    );
                }
            }
            for (uint256 i = 0; i < _cashbackRecipients[tokenId].length; i++) {
                // transferring cashback to authors
                uint256 cbvalue = (_cashbackValues[tokenId][i] * value) / 10000;
                if (_customToken[tokenId] == address(0)) {
                    cbvalue = _cashbackCalculator(
                        cbvalue,
                        _fixedValues[tokenId][i]
                    );
                    payable(_cashbackRecipients[tokenId][i]).transfer(cbvalue);
                } else {
                    cbvalue = _cashbackCalculator(
                        cbvalue,
                        _fixedValues[tokenId][i]
                    );
                    token.transferFrom(
                        to,
                        _cashbackRecipients[tokenId][i],
                        cbvalue
                    );
                }
            }
            if(_customToken[tokenId] == address(0) && msg.value>percentSum){
                payable(msg.sender).transfer(msg.value - percentSum);
            }
            if(_customToken[tokenId] != address(0) && msg.value>0){
                    payable(msg.sender).transfer(msg.value);
            }
        }
        _safeTransfer(msg.sender, to, tokenId, dataBytes);
        string calldata dataString = string(dataBytes);
        _appendTokenData(tokenId, dataString);
        emit TransferWithProvenance(tokenId, to, dataString[:index], value);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata dataBytes
    ) public payable virtual override {
        uint256 index;
        uint256 value;
        uint256 percentSum;
        IERC20 token;
        (index, value) = _bytesCheck(dataBytes);

        if (_customToken[tokenId] != address(0)) {
            token = IERC20(_customToken[tokenId]);
        }
        if (_cashbackRecipients[tokenId].length > 0) {
            for (uint256 i = 0; i < _cashbackValues[tokenId].length; i++) {
                uint256 iPercent = (_cashbackValues[tokenId][i] * value) /
                    10000;
                if (iPercent >= _fixedValues[tokenId][i]) {
                    percentSum += iPercent;
                } else {
                    percentSum += _fixedValues[tokenId][i];
                }
            }
            if (_customToken[tokenId] == address(0)) {
                if (percentSum > msg.value) {
                    payable(from).transfer(msg.value);
                    revert(
                        "Value should be greater than or equal to cashback value"
                    );
                }
            } else {
                if (percentSum > token.allowance(to, address(this))) {
                    revert(
                        "Insufficient ERC20 allowance balance for paying for the asset."
                    );
                }
            }
            for (uint256 i = 0; i < _cashbackRecipients[tokenId].length; i++) {
                // transferring cashback to authors
                uint256 cbvalue = (_cashbackValues[tokenId][i] * value) / 10000;
                if (_customToken[tokenId] == address(0)) {
                    cbvalue = _cashbackCalculator(
                        cbvalue,
                        _fixedValues[tokenId][i]
                    );
                    payable(_cashbackRecipients[tokenId][i]).transfer(cbvalue);
                } else {
                    cbvalue = _cashbackCalculator(
                        cbvalue,
                        _fixedValues[tokenId][i]
                    );

                    token.transferFrom(
                        to,
                        _cashbackRecipients[tokenId][i],
                        cbvalue
                    );
                }
            }
            if(_customToken[tokenId] != address(0) && msg.value>0){
                    payable(from).transfer(msg.value);
            }
            if(_customToken[tokenId] == address(0) && msg.value>percentSum){
                payable(from).transfer(msg.value - percentSum);
            }
        }
        _safeTransfer(from, to, tokenId, dataBytes);
        string calldata dataString = string(dataBytes);
        _appendTokenData(tokenId, dataString);
        emit TransferWithProvenance(tokenId, to, dataString[:index], value);
    }

    function _cashbackCalculator(uint256 x, uint256 y)
        private
        pure
        returns (uint256)
    {
        if (x >= y) {
            return x;
        }
        return y;
    }

    function _bytesCheck(bytes calldata dataBytes)
        private
        pure
        returns (uint256 index, uint256 value)
    {
        for (uint256 i = 0; i < dataBytes.length; i++) {
            if (
                dataBytes[i] == 0x27 &&
                dataBytes.length > i + 8 &&
                dataBytes[i + 1] == 0x27 &&
                dataBytes[i + 2] == 0x27 &&
                dataBytes[i + 3] == 0x23 &&
                dataBytes[i + 4] == 0x23 &&
                dataBytes[i + 5] == 0x23 &&
                dataBytes[i + 6] == 0x27 &&
                dataBytes[i + 7] == 0x27 &&
                dataBytes[i + 8] == 0x27
            ) {
                index = i;
                bytes calldata valueBytes = dataBytes[index + 9:];
                value = _stringToUint(string(valueBytes));
            }
        }
    }
}


// File contracts/tatum/Tatum721ProvenanceWithRoyaltyUpdate.sol

//SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
pragma experimental ABIEncoderV2;
contract Tatum721ProvenanceWithRoyaltyUpdate is
    ERC721Enumerable,
    ERC2981,
    ERC721URIStorage,
    AccessControlEnumerable
{
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant ROYALTY_UPDATER_ROLE = keccak256("ROYALTY_UPDATER_ROLE");
    mapping(uint256 => string[]) private _tokenData;
    mapping(uint256 => address[]) private _cashbackRecipients;
    mapping(uint256 => uint256[]) private _cashbackValues;
    mapping(uint256 => uint256[]) private _fixedValues;
    mapping(uint256 => address) private _customToken;
    bool _publicMint;

    event TransferWithProvenance(
        uint256 indexed id,
        address owner,
        string data,
        uint256 value
    );

        constructor(
        string memory name_,
        string memory symbol_,
        bool publicMint
    ) ERC721(name_, symbol_) {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());
        _setupRole(MINTER_ROLE, _msgSender());
        _publicMint = publicMint;
    }

    function royaltyInfo(uint256 tokenId, uint256 value)
        external
        view
        override
        returns (address, uint256)
    {
        uint256 result;
        uint256 cbvalue = (_cashbackValues[tokenId][0] * value) / 10000;
        result = _cashbackCalculator(cbvalue, _fixedValues[tokenId][0]);
        return (_cashbackRecipients[tokenId][0], result);
    }

    function _appendTokenData(uint256 tokenId, string calldata tokenData)
        internal
        virtual
    {
        require(
            _exists(tokenId),
            "ERC721URIStorage: URI set of nonexistent token"
        );
        _tokenData[tokenId].push(tokenData);
    }

    function mintWithTokenURI(
        address to,
        uint256 tokenId,
        string memory uri,
        address[] memory recipientAddresses,
        uint256[] memory cashbackValues,
        uint256[] memory fValues,
        address erc20
    ) public {
        require(
            erc20 != address(0),
            "Custom cashbacks cannot be set to 0 address"
        );
        _customToken[tokenId] = erc20;
        return
            mintWithTokenURI(
                to,
                tokenId,
                uri,
                recipientAddresses,
                cashbackValues,
                fValues
            );
    }

    function mintWithTokenURI(
        address to,
        uint256 tokenId,
        string memory uri,
        address[] memory recipientAddresses,
        uint256[] memory cashbackValues,
        uint256[] memory fValues
    ) public {
        if (!_publicMint) {
            require(
                hasRole(MINTER_ROLE, _msgSender()),
                "ERC721PresetMinterPauserAutoId: must have minter role to mint"
            );
        }
        _mint(to, tokenId);
        _setTokenURI(tokenId, uri);
        // saving cashback addresses and values
        if (recipientAddresses.length > 0) {
            _cashbackRecipients[tokenId] = recipientAddresses;
            _cashbackValues[tokenId] = cashbackValues;
            _fixedValues[tokenId] = fValues;
        }
    }

    function mintMultiple(
        address[] memory to,
        uint256[] memory tokenId,
        string[] memory uri,
        address[][] memory recipientAddresses,
        uint256[][] memory cashbackValues,
        uint256[][] memory fValues,
        address erc20
    ) public {
        require(
            erc20 != address(0),
            "Custom cashbacks cannot be set to 0 address"
        );
        for (uint256 i; i < to.length; i++) {
            _customToken[tokenId[i]] = erc20;
        }
        return
            mintMultiple(
                to,
                tokenId,
                uri,
                recipientAddresses,
                cashbackValues,
                fValues
            );
    }

    function mintMultiple(
        address[] memory to,
        uint256[] memory tokenId,
        string[] memory uri,
        address[][] memory recipientAddresses,
        uint256[][] memory cashbackValues,
        uint256[][] memory fValues
    ) public {
        if (!_publicMint) {
            require(
                hasRole(MINTER_ROLE, _msgSender()),
                "ERC721PresetMinterPauserAutoId: must have minter role to mint"
            );
        }
        for (uint256 i; i < to.length; i++) {
            _mint(to[i], tokenId[i]);
            _setTokenURI(tokenId[i], uri[i]);
            if (
                recipientAddresses.length > 0 &&
                recipientAddresses[i].length > 0
            ) {
                _cashbackRecipients[tokenId[i]] = recipientAddresses[i];
                _cashbackValues[tokenId[i]] = cashbackValues[i];
                _fixedValues[tokenId[i]] = fValues[i];
            }
        }
    }

    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(AccessControlEnumerable, ERC721, ERC721Enumerable, ERC2981)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }

    function tokenURI(uint256 tokenId)
        public
        view
        virtual
        override(ERC721, ERC721URIStorage)
        returns (string memory)
    {
        return ERC721URIStorage.tokenURI(tokenId);
    }

    function getCashbackAddress(uint256 tokenId)
        public
        view
        virtual
        returns (address)
    {
        return _customToken[tokenId];
    }

    function getTokenData(uint256 tokenId)
        public
        view
        virtual
        returns (string[] memory)
    {
        return _tokenData[tokenId];
    }

    function _beforeTokenTransfer(
        address from,
        address to,
        uint256 tokenId
    ) internal virtual override(ERC721, ERC721Enumerable) {
        super._beforeTokenTransfer(from, to, tokenId);
    }

    function _burn(uint256 tokenId)
        internal
        virtual
        override(ERC721, ERC721URIStorage)
    {
        return ERC721URIStorage._burn(tokenId);
    }

    function tokenCashbackValues(uint256 tokenId, uint256 tokenPrice)
        public
        view
        virtual
        returns (uint256[] memory)
    {
        uint256[] memory result = _cashbackValues[tokenId];
        for (uint256 i = 0; i < result.length; i++) {
            uint256 cbvalue = (result[i] * tokenPrice) / 10000;
            result[i] = _cashbackCalculator(cbvalue, _fixedValues[tokenId][i]);
        }
        return result;
    }

    function tokenCashbackRecipients(uint256 tokenId)
        public
        view
        virtual
        returns (address[] memory)
    {
        return _cashbackRecipients[tokenId];
    }

    function updateCashbackForAuthor(
        uint256 tokenId,
        address author,
        uint256 cashbackValue
    ) public {
        require(
            hasRole(ROYALTY_UPDATER_ROLE, _msgSender()),
            "ERC721PresetMinterPauserAutoId: must have ROYALTY_UPDATER_ROLE to update royalties"
        );
        for (uint256 i; i < _cashbackValues[tokenId].length; i++) {
            if (_cashbackRecipients[tokenId][i] == author) {
                _cashbackValues[tokenId][i] = cashbackValue;
            }
        }
    }

    function burn(uint256 tokenId) public virtual {
        //solhint-disable-next-line max-line-length
        require(
            _isApprovedOrOwner(_msgSender(), tokenId),
            "ERC721Burnable: caller is not owner nor approved"
        );
        _burn(tokenId);
    }

    function _stringToUint(string memory s)
        internal
        pure
        returns (uint256 result)
    {
        bytes memory b = bytes(s);
        // result = 0;
        for (uint256 i; i < b.length; i++) {
            uint256 c = uint256(uint8(b[i]));
            if (c >= 48 && c <= 57) {
                result = result * 10 + (c - 48);
            }
        }
    }

    function allowance(address a, uint256 t) public view returns (bool) {
        return _isApprovedOrOwner(a, t);
    }

    function safeTransfer(
        address to,
        uint256 tokenId,
        bytes calldata dataBytes
    ) public payable {
        uint256 index;
        uint256 value;
        uint256 percentSum;
        IERC20 token;
        (index, value) = _bytesCheck(dataBytes);
        if (_customToken[tokenId] != address(0)) {
            token = IERC20(_customToken[tokenId]);
        }
        if (_cashbackRecipients[tokenId].length > 0) {
            for (uint256 i = 0; i < _cashbackValues[tokenId].length; i++) {
                uint256 iPercent = (_cashbackValues[tokenId][i] * value) /
                    10000;
                if (iPercent >= _fixedValues[tokenId][i]) {
                    percentSum += iPercent;
                } else {
                    percentSum += _fixedValues[tokenId][i];
                }
            }
            if (_customToken[tokenId] == address(0)) {
                if (percentSum > msg.value) {
                    payable(msg.sender).transfer(msg.value);
                    revert(
                        "Value should be greater than or equal to cashback value"
                    );
                }
            } else {
                if (percentSum > token.allowance(to, address(this))) {
                    revert(
                        "Insufficient ERC20 allowance balance for paying for the asset."
                    );
                }
            }
            for (uint256 i = 0; i < _cashbackRecipients[tokenId].length; i++) {
                // transferring cashback to authors
                uint256 cbvalue = (_cashbackValues[tokenId][i] * value) / 10000;
                if (_customToken[tokenId] == address(0)) {
                    cbvalue = _cashbackCalculator(
                        cbvalue,
                        _fixedValues[tokenId][i]
                    );
                    payable(_cashbackRecipients[tokenId][i]).transfer(cbvalue);
                } else {
                    cbvalue = _cashbackCalculator(
                        cbvalue,
                        _fixedValues[tokenId][i]
                    );
                    token.transferFrom(
                        to,
                        _cashbackRecipients[tokenId][i],
                        cbvalue
                    );
                }
            }
            if (_customToken[tokenId] == address(0) && msg.value > percentSum) {
                payable(msg.sender).transfer(msg.value - percentSum);
            }
            if (_customToken[tokenId] != address(0) && msg.value > 0) {
                payable(msg.sender).transfer(msg.value);
            }
        }
        _safeTransfer(msg.sender, to, tokenId, dataBytes);
        string calldata dataString = string(dataBytes);
        _appendTokenData(tokenId, dataString);
        emit TransferWithProvenance(tokenId, to, dataString[:index], value);
    }

    function safeTransferFrom(
        address from,
        address to,
        uint256 tokenId,
        bytes calldata dataBytes
    ) public payable virtual override {
        uint256 index;
        uint256 value;
        uint256 percentSum;
        IERC20 token;
        (index, value) = _bytesCheck(dataBytes);

        if (_customToken[tokenId] != address(0)) {
            token = IERC20(_customToken[tokenId]);
        }
        if (_cashbackRecipients[tokenId].length > 0) {
            for (uint256 i = 0; i < _cashbackValues[tokenId].length; i++) {
                uint256 iPercent = (_cashbackValues[tokenId][i] * value) /
                    10000;
                if (iPercent >= _fixedValues[tokenId][i]) {
                    percentSum += iPercent;
                } else {
                    percentSum += _fixedValues[tokenId][i];
                }
            }
            if (_customToken[tokenId] == address(0)) {
                if (percentSum > msg.value) {
                    payable(from).transfer(msg.value);
                    revert(
                        "Value should be greater than or equal to cashback value"
                    );
                }
            } else {
                if (percentSum > token.allowance(to, address(this))) {
                    revert(
                        "Insufficient ERC20 allowance balance for paying for the asset."
                    );
                }
            }
            for (uint256 i = 0; i < _cashbackRecipients[tokenId].length; i++) {
                // transferring cashback to authors
                uint256 cbvalue = (_cashbackValues[tokenId][i] * value) / 10000;
                if (_customToken[tokenId] == address(0)) {
                    cbvalue = _cashbackCalculator(
                        cbvalue,
                        _fixedValues[tokenId][i]
                    );
                    payable(_cashbackRecipients[tokenId][i]).transfer(cbvalue);
                } else {
                    cbvalue = _cashbackCalculator(
                        cbvalue,
                        _fixedValues[tokenId][i]
                    );

                    token.transferFrom(
                        to,
                        _cashbackRecipients[tokenId][i],
                        cbvalue
                    );
                }
            }
            if (_customToken[tokenId] != address(0) && msg.value > 0) {
                payable(from).transfer(msg.value);
            }
            if (_customToken[tokenId] == address(0) && msg.value > percentSum) {
                payable(from).transfer(msg.value - percentSum);
            }
        }
        _safeTransfer(from, to, tokenId, dataBytes);
        string calldata dataString = string(dataBytes);
        _appendTokenData(tokenId, dataString);
        emit TransferWithProvenance(tokenId, to, dataString[:index], value);
    }

    function _cashbackCalculator(uint256 x, uint256 y)
        private
        pure
        returns (uint256)
    {
        if (x >= y) {
            return x;
        }
        return y;
    }

    function _bytesCheck(bytes calldata dataBytes)
        private
        pure
        returns (uint256 index, uint256 value)
    {
        for (uint256 i = 0; i < dataBytes.length; i++) {
            if (
                dataBytes[i] == 0x27 &&
                dataBytes.length > i + 8 &&
                dataBytes[i + 1] == 0x27 &&
                dataBytes[i + 2] == 0x27 &&
                dataBytes[i + 3] == 0x23 &&
                dataBytes[i + 4] == 0x23 &&
                dataBytes[i + 5] == 0x23 &&
                dataBytes[i + 6] == 0x27 &&
                dataBytes[i + 7] == 0x27 &&
                dataBytes[i + 8] == 0x27
            ) {
                index = i;
                bytes calldata valueBytes = dataBytes[index + 9:];
                value = _stringToUint(string(valueBytes));
            }
        }
    }
}


// File contracts/tatum/TatumCashback1155.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
contract Tatum1155 is Context, ERC165, IERC1155, IERC1155MetadataURI {
    using Address for address;
    // Mapping cashbacks and values to tokens
    mapping(uint256 => address[]) private _cashbackRecipients;
    mapping(uint256 => uint256[]) private _cashbackValues;
    // Mapping from token ID to account balances
    mapping(uint256 => mapping(address => uint256)) private _balances;

    // Mapping from account to operator approvals
    mapping(address => mapping(address => bool)) private _operatorApprovals;

    // Used as the URI for all token types by relying on ID substitution, e.g. https://token-cdn-domain/{id}.json
    string private _uri;

    /**
     * @dev See {_setURI}.
     */
    constructor(string memory uri_) {
        _setURI(uri_);
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId)
        public
        view
        virtual
        override(ERC165, IERC165)
        returns (bool)
    {
        return
            interfaceId == type(IERC1155).interfaceId ||
            interfaceId == type(IERC1155MetadataURI).interfaceId ||
            super.supportsInterface(interfaceId);
    }

    function uri(uint256)
        external
        view
        virtual
        override
        returns (string memory)
    {
        return _uri;
    }

    /**
     * @dev See {IERC1155-balanceOf}.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     */
    function balanceOf(address account, uint256 id)
        public
        view
        virtual
        override
        returns (uint256)
    {
        require(
            account != address(0),
            "ERC1155: balance query for the zero address"
        );
        return _balances[id][account];
    }

    /**
     * @dev See {IERC1155-balanceOfBatch}.
     *
     * Requirements:
     *
     * - `accounts` and `ids` must have the same length.
     */
    function balanceOfBatch(address[] memory accounts, uint256[] memory ids)
        public
        view
        virtual
        override
        returns (uint256[] memory)
    {
        require(
            accounts.length == ids.length,
            "ERC1155: accounts and ids length mismatch"
        );

        uint256[] memory batchBalances = new uint256[](accounts.length);

        for (uint256 i = 0; i < accounts.length; ++i) {
            batchBalances[i] = balanceOf(accounts[i], ids[i]);
        }

        return batchBalances;
    }

    /**
     * @dev See {IERC1155-setApprovalForAll}.
     */
    function setApprovalForAll(address, bool) public virtual override {
        require(false, "Not supported");
    }

    /**
     * @dev See {IERC1155-isApprovedForAll}.
     */
    function isApprovedForAll(address, address)
        public
        view
        virtual
        override
        returns (bool)
    {
        require(false, "Not supported");
        return false;
    }

    /**
     * @dev See {IERC1155-safeTransfer}.
     * Also sends cashback to authors if any
     */
    function safeTransfer(
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) public payable {
        require(to != address(0), "ERC1155: transfer to the zero address");
        address from = _msgSender();
        address operator = _msgSender();

        _beforeTokenTransfer(
            operator,
            from,
            to,
            _asSingletonArray(id),
            _asSingletonArray(amount),
            data
        );

        uint256 fromBalance = _balances[id][from];
        require(
            fromBalance >= amount,
            "ERC1155: insufficient balance for transfer"
        );
        _balances[id][from] = fromBalance - amount;
        _balances[id][to] += amount;
        if (_cashbackRecipients[id].length != 0) {
            uint256 sum = 0;
            for (uint256 i = 0; i < _cashbackValues[id].length; i++) {
                sum += _cashbackValues[id][i];
            }
            require(
                msg.value >= sum,
                "ERC1155: value must be greater than cashback values"
            );
            for (uint256 j = 0; j < _cashbackRecipients[id].length; j++) {
                // transferring cashback to authors
                payable(_cashbackRecipients[id][j]).transfer(
                    _cashbackValues[id][j]
                );
            }
            if (msg.value > sum) {
                payable(msg.sender).transfer(msg.value - sum);
            }
        } else {
            if (msg.value > 0) {
                payable(msg.sender).transfer(msg.value);
            }
        }
        emit TransferSingle(operator, from, to, id, amount);

        _doSafeTransferAcceptanceCheck(operator, from, to, id, amount, data);
    }

    /**
     * @dev See {IERC1155-safeBatchTransfer}.
     * Also sends cashback to authors if any
     */
    function safeBatchTransfer(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts
    ) public payable {
        require(
            ids.length == amounts.length,
            "ERC1155: ids and amounts length mismatch"
        );
        require(to != address(0), "ERC1155: transfer to the zero address");
        address from = _msgSender();
        address operator = _msgSender();
        uint256 bal = msg.value;
        //_beforeTokenTransfer(operator, from, to, ids, amounts, data);

        for (uint256 i = 0; i < ids.length; i++) {
            uint256 id = ids[i];
            uint256 amount = amounts[i];

            uint256 fromBalance = _balances[id][from];
            require(
                fromBalance >= amounts[i],
                "ERC1155: insufficient balance for transfer"
            );
            _balances[id][from] = fromBalance - amount;
            _balances[id][to] += amount;
            if (_cashbackRecipients[id].length != 0) {
                for (uint256 j = 0; j < _cashbackRecipients[id].length; j++) {
                    // transferring cashback to authors
                    payable(_cashbackRecipients[id][j]).transfer(
                        _cashbackValues[id][j]
                    );
                    bal = bal - _cashbackValues[id][j];
                }
            }
        }
        if (bal > 0) {
            payable(msg.sender).transfer(bal);
        }
        emit TransferBatch(operator, from, to, ids, amounts);
    }

    /**
     * @dev See {IERC1155-safeTransferFrom}.
     */
    function safeTransferFrom(
        address,
        address,
        uint256,
        uint256,
        bytes memory
    ) public virtual override {
        require(false, "Not supported");
    }

    /**
     * @dev See {IERC1155-safeBatchTransferFrom}.
     */
    function safeBatchTransferFrom(
        address,
        address,
        uint256[] memory,
        uint256[] memory,
        bytes memory
    ) public virtual override {
        require(false, "Not supported");
    }

    function _setURI(string memory newuri) internal virtual {
        _uri = newuri;
    }

    function _mint(
        address account,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) internal virtual {
        require(account != address(0), "ERC1155: mint to the zero address");

        address operator = _msgSender();

        _beforeTokenTransfer(
            operator,
            address(0),
            account,
            _asSingletonArray(id),
            _asSingletonArray(amount),
            data
        );

        _balances[id][account] += amount;
        emit TransferSingle(operator, address(0), account, id, amount);

        _doSafeTransferAcceptanceCheck(
            operator,
            address(0),
            account,
            id,
            amount,
            data
        );
    }

    function mint(
        address account,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) public {
        _mint(account, id, amount, data);
    }

    function burn(
        address account,
        uint256 id,
        uint256 amount
    ) public {
        _burn(account, id, amount);
    }

    function burnBatch(
        address account,
        uint256[] memory ids,
        uint256[] memory amounts
    ) public {
        _burnBatch(account, ids, amounts);
    }

    function mintBatch(
        address[] memory to,
        uint256[][] memory ids,
        uint256[][] memory amounts,
        bytes memory data
    ) public {
        for (uint256 i = 0; i < ids.length; i++) {
            _mintBatch(to[i], ids[i], amounts[i], data);
        }
    }

    function mintWithCashback(
        address account,
        uint256 id,
        uint256 amount,
        bytes memory data,
        address[] memory authorAddresses,
        uint256[] memory cashbackValues
    ) public {
        // saving cashback addresses and values
        _cashbackRecipients[id] = authorAddresses;
        _cashbackValues[id] = cashbackValues;
        _mint(account, id, amount, data);
    }

    function mintBatchWithCashback(
        address[] memory to,
        uint256[][] memory ids,
        uint256[][] memory amounts,
        bytes memory data,
        address[][][] memory authorAddresses,
        uint256[][][] memory cashbackValues
    ) public {
        for (uint256 i = 0; i < ids.length; i++) {
            _mintBatch(to[i], ids[i], amounts[i], data);
            for (uint256 j = 0; j < ids[i].length; j++) {
                _cashbackRecipients[ids[i][j]] = authorAddresses[i][j];
                _cashbackValues[ids[i][j]] = cashbackValues[i][j];
            }
        }
    }

    /**
     * Fetch cashback values and recipients for a token id, returns array
     */
    function tokenCashbackValues(uint256 tokenId)
        public
        view
        virtual
        returns (uint256[] memory)
    {
        return _cashbackValues[tokenId];
    }

    function tokenCashbackRecipients(uint256 tokenId)
        public
        view
        virtual
        returns (address[] memory)
    {
        return _cashbackRecipients[tokenId];
    }

    /**
     * To update the cashback values of an existing author, returns bool
     */
    function updateCashbackForAuthor(uint256 tokenId, uint256 cashbackValue)
        public
        returns (bool)
    {
        for (uint256 i = 0; i < _cashbackValues[tokenId].length; i++) {
            if (_cashbackRecipients[tokenId][i] == _msgSender()) {
                _cashbackValues[tokenId][i] = cashbackValue;
                return true;
            }
        }
        return true;
    }

    function _mintBatch(
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual {
        require(to != address(0), "ERC1155: mint to the zero address");
        require(
            ids.length == amounts.length,
            "ERC1155: ids and amounts length mismatch"
        );

        address operator = _msgSender();

        _beforeTokenTransfer(operator, address(0), to, ids, amounts, data);

        for (uint256 i = 0; i < ids.length; i++) {
            _balances[ids[i]][to] += amounts[i];
        }

        emit TransferBatch(operator, address(0), to, ids, amounts);

        _doSafeBatchTransferAcceptanceCheck(
            operator,
            address(0),
            to,
            ids,
            amounts,
            data
        );
    }

    function _burn(
        address account,
        uint256 id,
        uint256 amount
    ) internal virtual {
        require(account != address(0), "ERC1155: burn from the zero address");

        address operator = _msgSender();

        _beforeTokenTransfer(
            operator,
            account,
            address(0),
            _asSingletonArray(id),
            _asSingletonArray(amount),
            ""
        );

        uint256 accountBalance = _balances[id][account];
        require(
            accountBalance >= amount,
            "ERC1155: burn amount exceeds balance"
        );
        _balances[id][account] = accountBalance - amount;

        emit TransferSingle(operator, account, address(0), id, amount);
    }

    function _burnBatch(
        address account,
        uint256[] memory ids,
        uint256[] memory amounts
    ) internal virtual {
        require(account != address(0), "ERC1155: burn from the zero address");
        require(
            ids.length == amounts.length,
            "ERC1155: ids and amounts length mismatch"
        );

        address operator = _msgSender();

        _beforeTokenTransfer(operator, account, address(0), ids, amounts, "");

        for (uint256 i = 0; i < ids.length; i++) {
            uint256 id = ids[i];
            uint256 amount = amounts[i];

            uint256 accountBalance = _balances[id][account];
            require(
                accountBalance >= amount,
                "ERC1155: burn amount exceeds balance"
            );
            _balances[id][account] = accountBalance - amount;
        }

        emit TransferBatch(operator, account, address(0), ids, amounts);
    }

    function _beforeTokenTransfer(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) internal virtual {}

    function _doSafeTransferAcceptanceCheck(
        address operator,
        address from,
        address to,
        uint256 id,
        uint256 amount,
        bytes memory data
    ) private {
        if (to.isContract()) {
            try
                IERC1155Receiver(to).onERC1155Received(
                    operator,
                    from,
                    id,
                    amount,
                    data
                )
            returns (bytes4 response) {
                if (
                    response != IERC1155Receiver(to).onERC1155Received.selector
                ) {
                    revert("ERC1155: ERC1155Receiver rejected tokens");
                }
            } catch Error(string memory reason) {
                revert(reason);
            } catch {
                revert("ERC1155: transfer to non ERC1155Receiver implementer");
            }
        }
    }

    function _doSafeBatchTransferAcceptanceCheck(
        address operator,
        address from,
        address to,
        uint256[] memory ids,
        uint256[] memory amounts,
        bytes memory data
    ) private {
        if (to.isContract()) {
            try
                IERC1155Receiver(to).onERC1155BatchReceived(
                    operator,
                    from,
                    ids,
                    amounts,
                    data
                )
            returns (bytes4 response) {
                if (
                    response !=
                    IERC1155Receiver(to).onERC1155BatchReceived.selector
                ) {
                    revert("ERC1155: ERC1155Receiver rejected tokens");
                }
            } catch Error(string memory reason) {
                revert(reason);
            } catch {
                revert("ERC1155: transfer to non ERC1155Receiver implementer");
            }
        }
    }

    function _asSingletonArray(uint256 element)
        private
        pure
        returns (uint256[] memory)
    {
        uint256[] memory array = new uint256[](1);
        array[0] = element;

        return array;
    }
}


// File contracts/token/ERC1155/utils/ERC1155Receiver.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev _Available since v3.1._
 */
abstract contract ERC1155Receiver is ERC165, IERC1155Receiver {
    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(ERC165, IERC165) returns (bool) {
        return interfaceId == type(IERC1155Receiver).interfaceId
            || super.supportsInterface(interfaceId);
    }
}


// File contracts/token/ERC1155/utils/ERC1155Holder.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev _Available since v3.1._
 */
contract ERC1155Holder is ERC1155Receiver {
    function onERC1155Received(address, address, uint256, uint256, bytes memory) public virtual override returns (bytes4) {
        return this.onERC1155Received.selector;
    }

    function onERC1155BatchReceived(address, address, uint256[] memory, uint256[] memory, bytes memory) public virtual override returns (bytes4) {
        return this.onERC1155BatchReceived.selector;
    }
}


// File contracts/token/ERC20/presets/ERC20PresetFixedSupply.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
/**
 * @dev {ERC20} token, including:
 *
 *  - Preminted initial supply
 *  - Ability for holders to burn (destroy) their tokens
 *  - No access control mechanism (for minting/pausing) and hence no governance
 *
 * This contract uses {ERC20Burnable} to include burn capabilities - head to
 * its documentation for details.
 *
 * _Available since v3.4._
 */
contract ERC20PresetFixedSupply is ERC20Burnable {
    /**
     * @dev Mints `initialSupply` amount of token and transfers them to `owner`.
     *
     * See {ERC20-constructor}.
     */
    constructor(
        string memory name,
        string memory symbol,
        uint256 initialSupply,
        address owner
    ) ERC20(name, symbol) {
        _mint(owner, initialSupply);
    }
}


// File contracts/token/ERC20/presets/ERC20PresetMinterPauser.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev {ERC20} token, including:
 *
 *  - ability for holders to burn (destroy) their tokens
 *  - a minter role that allows for token minting (creation)
 *  - a pauser role that allows to stop all token transfers
 *
 * This contract uses {AccessControl} to lock permissioned functions using the
 * different roles - head to its documentation for details.
 *
 * The account that deploys the contract will be granted the minter and pauser
 * roles, as well as the default admin role, which will let it grant both minter
 * and pauser roles to other accounts.
 */
contract ERC20PresetMinterPauser is Context, AccessControlEnumerable, ERC20Burnable, ERC20Pausable {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    /**
     * @dev Grants `DEFAULT_ADMIN_ROLE`, `MINTER_ROLE` and `PAUSER_ROLE` to the
     * account that deploys the contract.
     *
     * See {ERC20-constructor}.
     */
    constructor(string memory name, string memory symbol) ERC20(name, symbol) {
        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        _setupRole(MINTER_ROLE, _msgSender());
        _setupRole(PAUSER_ROLE, _msgSender());
    }

    /**
     * @dev Creates `amount` new tokens for `to`.
     *
     * See {ERC20-_mint}.
     *
     * Requirements:
     *
     * - the caller must have the `MINTER_ROLE`.
     */
    function mint(address to, uint256 amount) public virtual {
        require(hasRole(MINTER_ROLE, _msgSender()), "ERC20PresetMinterPauser: must have minter role to mint");
        _mint(to, amount);
    }

    /**
     * @dev Pauses all token transfers.
     *
     * See {ERC20Pausable} and {Pausable-_pause}.
     *
     * Requirements:
     *
     * - the caller must have the `PAUSER_ROLE`.
     */
    function pause() public virtual {
        require(hasRole(PAUSER_ROLE, _msgSender()), "ERC20PresetMinterPauser: must have pauser role to pause");
        _pause();
    }

    /**
     * @dev Unpauses all token transfers.
     *
     * See {ERC20Pausable} and {Pausable-_unpause}.
     *
     * Requirements:
     *
     * - the caller must have the `PAUSER_ROLE`.
     */
    function unpause() public virtual {
        require(hasRole(PAUSER_ROLE, _msgSender()), "ERC20PresetMinterPauser: must have pauser role to unpause");
        _unpause();
    }

    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual override(ERC20, ERC20Pausable) {
        super._beforeTokenTransfer(from, to, amount);
    }
}


// File contracts/token/ERC20/utils/TokenTimelock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev A token holder contract that will allow a beneficiary to extract the
 * tokens after a given release time.
 *
 * Useful for simple vesting schedules like "advisors get all of their tokens
 * after 1 year".
 */
contract TokenTimelock {
    using SafeERC20 for IERC20;

    // ERC20 basic token contract being held
    IERC20 immutable private _token;

    // beneficiary of tokens after they are released
    address immutable private _beneficiary;

    // timestamp when token release is enabled
    uint256 immutable private _releaseTime;

    constructor (IERC20 token_, address beneficiary_, uint256 releaseTime_) {
        // solhint-disable-next-line not-rely-on-time
        require(releaseTime_ > block.timestamp, "TokenTimelock: release time is before current time");
        _token = token_;
        _beneficiary = beneficiary_;
        _releaseTime = releaseTime_;
    }

    /**
     * @return the token being held.
     */
    function token() public view virtual returns (IERC20) {
        return _token;
    }

    /**
     * @return the beneficiary of the tokens.
     */
    function beneficiary() public view virtual returns (address) {
        return _beneficiary;
    }

    /**
     * @return the time when the tokens are released.
     */
    function releaseTime() public view virtual returns (uint256) {
        return _releaseTime;
    }

    /**
     * @notice Transfers tokens held by timelock to beneficiary.
     */
    function release() public virtual {
        // solhint-disable-next-line not-rely-on-time
        require(block.timestamp >= releaseTime(), "TokenTimelock: current time is before release time");

        uint256 amount = token().balanceOf(address(this));
        require(amount > 0, "TokenTimelock: no tokens to release");

        token().safeTransfer(beneficiary(), amount);
    }
}


// File contracts/token/ERC721/presets/ERC721PresetMinterPauserAutoId.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @dev {ERC721} token, including:
 *
 *  - ability for holders to burn (destroy) their tokens
 *  - a minter role that allows for token minting (creation)
 *  - a pauser role that allows to stop all token transfers
 *  - token ID and URI autogeneration
 *
 * This contract uses {AccessControl} to lock permissioned functions using the
 * different roles - head to its documentation for details.
 *
 * The account that deploys the contract will be granted the minter and pauser
 * roles, as well as the default admin role, which will let it grant both minter
 * and pauser roles to other accounts.
 */
contract ERC721PresetMinterPauserAutoId is Context, AccessControlEnumerable, ERC721Enumerable, ERC721Burnable, ERC721Pausable {
    using Counters for Counters.Counter;

    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant PAUSER_ROLE = keccak256("PAUSER_ROLE");

    Counters.Counter private _tokenIdTracker;

    string private _baseTokenURI;

    /**
     * @dev Grants `DEFAULT_ADMIN_ROLE`, `MINTER_ROLE` and `PAUSER_ROLE` to the
     * account that deploys the contract.
     *
     * Token URIs will be autogenerated based on `baseURI` and their token IDs.
     * See {ERC721-tokenURI}.
     */
    constructor(string memory name, string memory symbol, string memory baseTokenURI) ERC721(name, symbol) {
        _baseTokenURI = baseTokenURI;

        _setupRole(DEFAULT_ADMIN_ROLE, _msgSender());

        _setupRole(MINTER_ROLE, _msgSender());
        _setupRole(PAUSER_ROLE, _msgSender());
    }

    function _baseURI() internal view virtual override returns (string memory) {
        return _baseTokenURI;
    }

    /**
     * @dev Creates a new token for `to`. Its token ID will be automatically
     * assigned (and available on the emitted {IERC721-Transfer} event), and the token
     * URI autogenerated based on the base URI passed at construction.
     *
     * See {ERC721-_mint}.
     *
     * Requirements:
     *
     * - the caller must have the `MINTER_ROLE`.
     */
    function mint(address to) public virtual {
        require(hasRole(MINTER_ROLE, _msgSender()), "ERC721PresetMinterPauserAutoId: must have minter role to mint");

        // We cannot just use balanceOf to create the new tokenId because tokens
        // can be burned (destroyed), so we need a separate counter.
        _mint(to, _tokenIdTracker.current());
        _tokenIdTracker.increment();
    }

    /**
     * @dev Pauses all token transfers.
     *
     * See {ERC721Pausable} and {Pausable-_pause}.
     *
     * Requirements:
     *
     * - the caller must have the `PAUSER_ROLE`.
     */
    function pause() public virtual {
        require(hasRole(PAUSER_ROLE, _msgSender()), "ERC721PresetMinterPauserAutoId: must have pauser role to pause");
        _pause();
    }

    /**
     * @dev Unpauses all token transfers.
     *
     * See {ERC721Pausable} and {Pausable-_unpause}.
     *
     * Requirements:
     *
     * - the caller must have the `PAUSER_ROLE`.
     */
    function unpause() public virtual {
        require(hasRole(PAUSER_ROLE, _msgSender()), "ERC721PresetMinterPauserAutoId: must have pauser role to unpause");
        _unpause();
    }

    function _beforeTokenTransfer(address from, address to, uint256 tokenId) internal virtual override(ERC721, ERC721Enumerable, ERC721Pausable) {
        super._beforeTokenTransfer(from, to, tokenId);
    }

    /**
     * @dev See {IERC165-supportsInterface}.
     */
    function supportsInterface(bytes4 interfaceId) public view virtual override(AccessControlEnumerable, ERC721, ERC721Enumerable) returns (bool) {
        return super.supportsInterface(interfaceId);
    }
}


// File contracts/token/ERC721/utils/ERC721Holder.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
  /**
   * @dev Implementation of the {IERC721Receiver} interface.
   *
   * Accepts all token transfers.
   * Make sure the contract is able to use its token with {IERC721-safeTransferFrom}, {IERC721-approve} or {IERC721-setApprovalForAll}.
   */
contract ERC721Holder is IERC721Receiver {

    /**
     * @dev See {IERC721Receiver-onERC721Received}.
     *
     * Always returns `IERC721Receiver.onERC721Received.selector`.
     */
    function onERC721Received(address, address, uint256, bytes memory) public virtual override returns (bytes4) {
        return this.onERC721Received.selector;
    }
}


// File contracts/token/ERC777/presets/ERC777PresetFixedSupply.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;
/**
 * @dev {ERC777} token, including:
 *
 *  - Preminted initial supply
 *  - No access control mechanism (for minting/pausing) and hence no governance
 *
 * _Available since v3.4._
 */
contract ERC777PresetFixedSupply is ERC777 {
    /**
     * @dev Mints `initialSupply` amount of token and transfers them to `owner`.
     *
     * See {ERC777-constructor}.
     */
    constructor(
        string memory name,
        string memory symbol,
        address[] memory defaultOperators,
        uint256 initialSupply,
        address owner
    ) ERC777(name, symbol, defaultOperators) {
        _mint(owner, initialSupply, "", "");
    }
}


// File contracts/utils/escrow/RefundEscrow.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title RefundEscrow
 * @dev Escrow that holds funds for a beneficiary, deposited from multiple
 * parties.
 * @dev Intended usage: See {Escrow}. Same usage guidelines apply here.
 * @dev The owner account (that is, the contract that instantiates this
 * contract) may deposit, close the deposit period, and allow for either
 * withdrawal by the beneficiary, or refunds to the depositors. All interactions
 * with `RefundEscrow` will be made through the owner contract.
 */
contract RefundEscrow is ConditionalEscrow {
    using Address for address payable;

    enum State { Active, Refunding, Closed }

    event RefundsClosed();
    event RefundsEnabled();

    State private _state;
    address payable immutable private _beneficiary;

    /**
     * @dev Constructor.
     * @param beneficiary_ The beneficiary of the deposits.
     */
    constructor (address payable beneficiary_) {
        require(beneficiary_ != address(0), "RefundEscrow: beneficiary is the zero address");
        _beneficiary = beneficiary_;
        _state = State.Active;
    }

    /**
     * @return The current state of the escrow.
     */
    function state() public view virtual returns (State) {
        return _state;
    }

    /**
     * @return The beneficiary of the escrow.
     */
    function beneficiary() public view virtual returns (address payable) {
        return _beneficiary;
    }

    /**
     * @dev Stores funds that may later be refunded.
     * @param refundee The address funds will be sent to if a refund occurs.
     */
    function deposit(address refundee) public payable virtual override {
        require(state() == State.Active, "RefundEscrow: can only deposit while active");
        super.deposit(refundee);
    }

    /**
     * @dev Allows for the beneficiary to withdraw their funds, rejecting
     * further deposits.
     */
    function close() public virtual onlyOwner {
        require(state() == State.Active, "RefundEscrow: can only close while active");
        _state = State.Closed;
        emit RefundsClosed();
    }

    /**
     * @dev Allows for refunds to take place, rejecting further deposits.
     */
    function enableRefunds() public onlyOwner virtual {
        require(state() == State.Active, "RefundEscrow: can only enable refunds while active");
        _state = State.Refunding;
        emit RefundsEnabled();
    }

    /**
     * @dev Withdraws the beneficiary's funds.
     */
    function beneficiaryWithdraw() public virtual {
        require(state() == State.Closed, "RefundEscrow: beneficiary can only withdraw while closed");
        beneficiary().sendValue(address(this).balance);
    }

    /**
     * @dev Returns whether refundees can withdraw their deposits (be refunded). The overridden function receives a
     * 'payee' argument, but we ignore it here since the condition is global, not per-payee.
     */
    function withdrawalAllowed(address) public view override returns (bool) {
        return state() == State.Refunding;
    }
}


// File contracts/utils/PaymentSplitter.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;
/**
 * @title PaymentSplitter
 * @dev This contract allows to split Ether payments among a group of accounts. The sender does not need to be aware
 * that the Ether will be split in this way, since it is handled transparently by the contract.
 *
 * The split can be in equal parts or in any other arbitrary proportion. The way this is specified is by assigning each
 * account to a number of shares. Of all the Ether that this contract receives, each account will then be able to claim
 * an amount proportional to the percentage of total shares they were assigned.
 *
 * `PaymentSplitter` follows a _pull payment_ model. This means that payments are not automatically forwarded to the
 * accounts but kept in this contract, and the actual transfer is triggered as a separate step by calling the {release}
 * function.
 */
contract PaymentSplitter is Context {
    event PayeeAdded(address account, uint256 shares);
    event PaymentReleased(address to, uint256 amount);
    event PaymentReceived(address from, uint256 amount);

    uint256 private _totalShares;
    uint256 private _totalReleased;

    mapping(address => uint256) private _shares;
    mapping(address => uint256) private _released;
    address[] private _payees;

    /**
     * @dev Creates an instance of `PaymentSplitter` where each account in `payees` is assigned the number of shares at
     * the matching position in the `shares` array.
     *
     * All addresses in `payees` must be non-zero. Both arrays must have the same non-zero length, and there must be no
     * duplicates in `payees`.
     */
    constructor (address[] memory payees, uint256[] memory shares_) payable {
        // solhint-disable-next-line max-line-length
        require(payees.length == shares_.length, "PaymentSplitter: payees and shares length mismatch");
        require(payees.length > 0, "PaymentSplitter: no payees");

        for (uint256 i = 0; i < payees.length; i++) {
            _addPayee(payees[i], shares_[i]);
        }
    }

    /**
     * @dev The Ether received will be logged with {PaymentReceived} events. Note that these events are not fully
     * reliable: it's possible for a contract to receive Ether without triggering this function. This only affects the
     * reliability of the events, and not the actual splitting of Ether.
     *
     * To learn more about this see the Solidity documentation for
     * https://solidity.readthedocs.io/en/latest/contracts.html#fallback-function[fallback
     * functions].
     */
    receive () external payable virtual {
        emit PaymentReceived(_msgSender(), msg.value);
    }

    /**
     * @dev Getter for the total shares held by payees.
     */
    function totalShares() public view returns (uint256) {
        return _totalShares;
    }

    /**
     * @dev Getter for the total amount of Ether already released.
     */
    function totalReleased() public view returns (uint256) {
        return _totalReleased;
    }

    /**
     * @dev Getter for the amount of shares held by an account.
     */
    function shares(address account) public view returns (uint256) {
        return _shares[account];
    }

    /**
     * @dev Getter for the amount of Ether already released to a payee.
     */
    function released(address account) public view returns (uint256) {
        return _released[account];
    }

    /**
     * @dev Getter for the address of the payee number `index`.
     */
    function payee(uint256 index) public view returns (address) {
        return _payees[index];
    }

    /**
     * @dev Triggers a transfer to `account` of the amount of Ether they are owed, according to their percentage of the
     * total shares and their previous withdrawals.
     */
    function release(address payable account) public virtual {
        require(_shares[account] > 0, "PaymentSplitter: account has no shares");

        uint256 totalReceived = address(this).balance + _totalReleased;
        uint256 payment = totalReceived * _shares[account] / _totalShares - _released[account];

        require(payment != 0, "PaymentSplitter: account is not due payment");

        _released[account] = _released[account] + payment;
        _totalReleased = _totalReleased + payment;

        Address.sendValue(account, payment);
        emit PaymentReleased(account, payment);
    }

    /**
     * @dev Add a new payee to the contract.
     * @param account The address of the payee to add.
     * @param shares_ The number of shares owned by the payee.
     */
    function _addPayee(address account, uint256 shares_) private {
        require(account != address(0), "PaymentSplitter: account is the zero address");
        require(shares_ > 0, "PaymentSplitter: shares are 0");
        require(_shares[account] == 0, "PaymentSplitter: account already has shares");

        _payees.push(account);
        _shares[account] = shares_;
        _totalShares = _totalShares + shares_;
        emit PayeeAdded(account, shares_);
    }
}


// File contracts/mocks/BadBeacon.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract BadBeaconNoImpl {
}

contract BadBeaconNotContract {
    function implementation() external pure returns (address) {
        return address(0x1);
    }
}


// File contracts/mocks/CallReceiverMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract CallReceiverMock {
    string public sharedAnswer;

    event MockFunctionCalled();

    uint256[] private _array;

    function mockFunction() public payable returns (string memory) {
        emit MockFunctionCalled();

        return "0x1234";
    }

    function mockFunctionNonPayable() public returns (string memory) {
        emit MockFunctionCalled();

        return "0x1234";
    }

    function mockStaticFunction() public pure returns (string memory) {
        return "0x1234";
    }

    function mockFunctionRevertsNoReason() public payable {
        revert();
    }

    function mockFunctionRevertsReason() public payable {
        revert("CallReceiverMock: reverting");
    }

    function mockFunctionThrows() public payable {
        assert(false);
    }

    function mockFunctionOutOfGas() public payable {
        for (uint256 i = 0; ; ++i) {
            _array.push(i);
        }
    }

    function mockFunctionWritesStorage() public returns (string memory) {
        sharedAnswer = "42";
        return "0x1234";
    }
}


// File contracts/mocks/ClashingImplementation.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;


/**
 * @dev Implementation contract with an admin() function made to clash with
 * @dev TransparentUpgradeableProxy's to test correct functioning of the
 * @dev Transparent Proxy feature.
 */
contract ClashingImplementation {

  function admin() external pure returns (address) {
    return 0x0000000000000000000000000000000011111142;
  }

  function delegatedFunction() external pure returns (bool) {
    return true;
  }
}


// File contracts/mocks/DummyImplementation.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

abstract contract Impl {
  function version() public pure virtual returns (string memory); 
}

contract DummyImplementation {
  uint256 public value;
  string public text;
  uint256[] public values;

  function initializeNonPayable() public {
    value = 10;
  }

  function initializePayable() public payable {
    value = 100;
  }

  function initializeNonPayableWithValue(uint256 _value) public {
    value = _value;
  }

  function initializePayableWithValue(uint256 _value) public payable {
    value = _value;
  }

  function initialize(uint256 _value, string memory _text, uint256[] memory _values) public {
    value = _value;
    text = _text;
    values = _values;
  }

  function get() public pure returns (bool) {
    return true;
  }

  function version() public pure virtual returns (string memory) {
    return "V1";
  }

  function reverts() public pure {
    require(false, "DummyImplementation reverted");
  }
}

contract DummyImplementationV2 is DummyImplementation {
  function migrate(uint256 newVal) public payable {
    value = newVal;
  }

  function version() public pure override returns (string memory) {
    return "V2";
  }
}


// File contracts/mocks/ERC165/ERC165MissingData.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract ERC165MissingData {
    function supportsInterface(bytes4 interfaceId) public view {} // missing return
}


// File contracts/mocks/ERC165/ERC165NotSupported.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract ERC165NotSupported { }


// File contracts/mocks/EtherReceiverMock.sol

// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract EtherReceiverMock {
    bool private _acceptEther;

    function setAcceptEther(bool acceptEther) public {
        _acceptEther = acceptEther;
    }

    receive () external payable {
        if (!_acceptEther) {
            revert();
        }
    }
}


// File contracts/ProassetzToken.sol

// SPDX-License-Identifier: MIT
pragma solidity ^0.6.12;

abstract contract Context {
    function _msgSender() internal view virtual returns (address payable) {
        return msg.sender;
    }

    function _msgData() internal view virtual returns (bytes memory) {
        this;
        // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
        return msg.data;
    }
}

/**
 * @dev Contract module which provides a basic access control mechanism, where
 * there is an account (an owner) that can be granted exclusive access to
 * specific functions.
 *
 * By default, the owner account will be the one that deploys the contract. This
 * can later be changed with {transferOwnership}.
 *
 * This module is used through inheritance. It will make available the modifier
 * `onlyOwner`, which can be applied to your functions to restrict their use to
 * the owner.
 */
abstract contract Ownable is Context {
    address private _owner;

    event OwnershipTransferred(address indexed previousOwner, address indexed newOwner);

    /**
     * @dev Initializes the contract setting the deployer as the initial owner.
     */
    constructor () internal {
        address msgSender = _msgSender();
        _owner = msgSender;
        emit OwnershipTransferred(address(0), msgSender);
    }

    /**
     * @dev Returns the address of the current owner.
     */
    function owner() public view returns (address) {
        return _owner;
    }

    /**
     * @dev Throws if called by any account other than the owner.
     */
    modifier onlyOwner() {
        require(_owner == _msgSender(), "Ownable: caller is not the owner");
        _;
    }

    /**
     * @dev Leaves the contract without owner. It will not be possible to call
     * `onlyOwner` functions anymore. Can only be called by the current owner.
     *
     * NOTE: Renouncing ownership will leave the contract without an owner,
     * thereby removing any functionality that is only available to the owner.
     */
    function renounceOwnership() public virtual onlyOwner {
        emit OwnershipTransferred(_owner, address(0));
        _owner = address(0);
    }

    /**
     * @dev Transfers ownership of the contract to a new account (`newOwner`).
     * Can only be called by the current owner.
     */
    function transferOwnership(address newOwner) public virtual onlyOwner {
        require(newOwner != address(0), "Ownable: new owner is the zero address");
        emit OwnershipTransferred(_owner, newOwner);
        _owner = newOwner;
    }
}

abstract contract Blacklistable is Ownable {

    mapping(address => bool) internal blacklisted;

    event Blacklisted(address indexed _account);
    event Whitelisted(address indexed _account);

    /**
     * @dev Checks if account is blacklisted
     * @param _account The address to check    
    */
    function isBlacklisted(address _account) public view returns (bool) {
        return blacklisted[_account];
    }

    /**
     * @dev Adds account to blacklist
     * @param _account The address to blacklist
    */
    function blacklist(address _account) public onlyOwner {
        blacklisted[_account] = true;
        emit Blacklisted(_account);
    }

    /**
     * @dev Removes account from blacklist
     * @param _account The address to remove from the blacklist
    */
    function whitelist(address _account) public onlyOwner {
        blacklisted[_account] = false;
        emit Whitelisted(_account);
    }
}

/*
 * @dev Provides information about the current execution context, including the
 * sender of the transaction and its data. While these are generally available
 * via msg.sender and msg.data, they should not be accessed in such a direct
 * manner, since when dealing with GSN meta-transactions the account sending and
 * paying for execution may not be the actual sender (as far as an application
 * is concerned).
 *
 * This contract is only required for intermediate, library-like contracts.
 */

abstract contract Pausable is Context {
    /**
     * @dev Emitted when the pause is triggered by `account`.
     */
    event Paused(address account);

    /**
     * @dev Emitted when the pause is lifted by `account`.
     */
    event Unpaused(address account);

    bool private _paused;

    /**
     * @dev Initializes the contract in unpaused state.
     */
    constructor () public {
        _paused = false;
    }

    /**
     * @dev Returns true if the contract is paused, and false otherwise.
     */
    function paused() public view virtual returns (bool) {
        return _paused;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is not paused.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    modifier whenNotPaused() {
        require(!paused(), "Pausable: paused");
        _;
    }

    /**
     * @dev Modifier to make a function callable only when the contract is paused.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    modifier whenPaused() {
        require(paused(), "Pausable: not paused");
        _;
    }

    /**
     * @dev Triggers stopped state.
     *
     * Requirements:
     *
     * - The contract must not be paused.
     */
    function _pause() internal virtual whenNotPaused {
        _paused = true;
        emit Paused(_msgSender());
    }

    /**
     * @dev Returns to normal state.
     *
     * Requirements:
     *
     * - The contract must be paused.
     */
    function _unpause() internal virtual whenPaused {
        _paused = false;
        emit Unpaused(_msgSender());
    }
}

/**
 * @dev Interface of the ERC20 standard as defined in the EIP.
 */
interface IERC20 {
    /**
     * @dev Returns the amount of tokens in existence.
     */
    function totalSupply() external view returns (uint256);

    /**
     * @dev Returns the amount of tokens owned by `account`.
     */
    function balanceOf(address account) external view returns (uint256);

    /**
     * @dev Moves `amount` tokens from the caller's account to `recipient`.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transfer(address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Returns the remaining number of tokens that `spender` will be
     * allowed to spend on behalf of `owner` through {transferFrom}. This is
     * zero by default.
     *
     * This value changes when {approve} or {transferFrom} are called.
     */
    function allowance(address owner, address spender) external view returns (uint256);

    /**
     * @dev Sets `amount` as the allowance of `spender` over the caller's tokens.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * IMPORTANT: Beware that changing an allowance with this method brings the risk
     * that someone may use both the old and the new allowance by unfortunate
     * transaction ordering. One possible solution to mitigate this race
     * condition is to first reduce the spender's allowance to 0 and set the
     * desired value afterwards:
     * https://github.com/ethereum/EIPs/issues/20#issuecomment-263524729
     *
     * Emits an {Approval} event.
     */
    function approve(address spender, uint256 amount) external returns (bool);

    /**
     * @dev Moves `amount` tokens from `sender` to `recipient` using the
     * allowance mechanism. `amount` is then deducted from the caller's
     * allowance.
     *
     * Returns a boolean value indicating whether the operation succeeded.
     *
     * Emits a {Transfer} event.
     */
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);

    /**
     * @dev Emitted when `value` tokens are moved from one account (`from`) to
     * another (`to`).
     *
     * Note that `value` may be zero.
     */
    event Transfer(address indexed from, address indexed to, uint256 value);

    /**
     * @dev Emitted when the allowance of a `spender` for an `owner` is set by
     * a call to {approve}. `value` is the new allowance.
     */
    event Approval(address indexed owner, address indexed spender, uint256 value);
}

contract ERC20 is Context, IERC20 {
    using SafeMath for uint256;

    mapping(address => uint256) private _balances;

    mapping(address => mapping(address => uint256)) private _allowances;

    uint256 private _totalSupply;

    string private _name;
    string private _symbol;
    uint8 private _decimals;
    uint256 immutable private _cap;

    constructor (string memory name_, string memory symbol_, uint256 cap_) public {
        require(cap_ > 0, "ERC20Capped: cap is 0");
        _cap = cap_;
        _name = name_;
        _symbol = symbol_;
        _decimals = 8;
    }

    /**
     * @dev Returns the cap on the token's total supply.
     */
    function cap() public view virtual returns (uint256) {
        return _cap;
    }
    
    /**
     * @dev Returns the name of the token.
     */
    function name() public view returns (string memory) {
        return _name;
    }

    /**
     * @dev Returns the symbol of the token, usually a shorter version of the
     * name.
     */
    function symbol() public view returns (string memory) {
        return _symbol;
    }

    /**
     * @dev Returns the number of decimals used to get its user representation.
     * For example, if `decimals` equals `2`, a balance of `505` tokens should
     * be displayed to a user as `5,05` (`505 / 10 ** 2`).
     *
     * NOTE: This information is only used for _display_ purposes: it in
     * no way affects any of the arithmetic of the contract, including
     * {IERC20-balanceOf} and {IERC20-transfer}.
     */
    function decimals() public view returns (uint8) {
        return _decimals;
    }

    /**
     * @dev See {IERC20-totalSupply}.
     */
    function totalSupply() public view override returns (uint256) {
        return _totalSupply;
    }

    /**
     * @dev See {IERC20-balanceOf}.
     */
    function balanceOf(address account) public view override returns (uint256) {
        return _balances[account];
    }

    /**
     * @dev See {IERC20-transfer}.
     *
     * Requirements:
     *
     * - `recipient` cannot be the zero address.
     * - the caller must have a balance of at least `amount`.
     */
    function transfer(address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(_msgSender(), recipient, amount);
        return true;
    }

    /**
     * @dev See {IERC20-allowance}.
     */
    function allowance(address owner, address spender) public view virtual override returns (uint256) {
        return _allowances[owner][spender];
    }

    /**
     * @dev See {IERC20-approve}.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function approve(address spender, uint256 amount) public virtual override returns (bool) {
        _approve(_msgSender(), spender, amount);
        return true;
    }

    /**
     * @dev See {IERC20-transferFrom}.
     *
     * Emits an {Approval} event indicating the updated allowance. This is not
     * required by the EIP. See the note at the beginning of {ERC20}.
     *
     * Requirements:
     *
     * - `sender` and `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     * - the caller must have allowance for ``sender``'s tokens of at least
     * `amount`.
     */
    function transferFrom(address sender, address recipient, uint256 amount) public virtual override returns (bool) {
        _transfer(sender, recipient, amount);
        _approve(sender, _msgSender(), _allowances[sender][_msgSender()].sub(amount, "ERC20: transfer amount exceeds allowance"));
        return true;
    }

    /**
     * @dev Atomically increases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     */
    function increaseAllowance(address spender, uint256 addedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].add(addedValue));
        return true;
    }

    /**
     * @dev Atomically decreases the allowance granted to `spender` by the caller.
     *
     * This is an alternative to {approve} that can be used as a mitigation for
     * problems described in {IERC20-approve}.
     *
     * Emits an {Approval} event indicating the updated allowance.
     *
     * Requirements:
     *
     * - `spender` cannot be the zero address.
     * - `spender` must have allowance for the caller of at least
     * `subtractedValue`.
     */
    function decreaseAllowance(address spender, uint256 subtractedValue) public virtual returns (bool) {
        _approve(_msgSender(), spender, _allowances[_msgSender()][spender].sub(subtractedValue, "ERC20: decreased allowance below zero"));
        return true;
    }

    /**
     * @dev Moves tokens `amount` from `sender` to `recipient`.
     *
     * This is internal function is equivalent to {transfer}, and can be used to
     * e.g. implement automatic token fees, slashing mechanisms, etc.
     *
     * Emits a {Transfer} event.
     *
     * Requirements:
     *
     * - `sender` cannot be the zero address.
     * - `recipient` cannot be the zero address.
     * - `sender` must have a balance of at least `amount`.
     */
    function _transfer(address sender, address recipient, uint256 amount) internal virtual {
        require(sender != address(0), "ERC20: transfer from the zero address");
        require(recipient != address(0), "ERC20: transfer to the zero address");

        _beforeTokenTransfer(sender, recipient, amount);

        _balances[sender] = _balances[sender].sub(amount, "ERC20: transfer amount exceeds balance");
        _balances[recipient] = _balances[recipient].add(amount);
        emit Transfer(sender, recipient, amount);
    }

    /** @dev Creates `amount` tokens and assigns them to `account`, increasing
     * the total supply.
     *
     * Emits a {Transfer} event with `from` set to the zero address.
     *
     * Requirements:
     *
     * - `to` cannot be the zero address.
     */
    function _mint(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: mint to the zero address");
        _beforeTokenTransfer(address(0), account, amount);

        _totalSupply = _totalSupply.add(amount);
        _balances[account] = _balances[account].add(amount);
        emit Transfer(address(0), account, amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`, reducing the
     * total supply.
     *
     * Emits a {Transfer} event with `to` set to the zero address.
     *
     * Requirements:
     *
     * - `account` cannot be the zero address.
     * - `account` must have at least `amount` tokens.
     */
    function _burn(address account, uint256 amount) internal virtual {
        require(account != address(0), "ERC20: burn from the zero address");

        _beforeTokenTransfer(account, address(0), amount);

        _balances[account] = _balances[account].sub(amount, "ERC20: burn amount exceeds balance");
        _totalSupply = _totalSupply.sub(amount);
        emit Transfer(account, address(0), amount);
    }

    /**
     * @dev Sets `amount` as the allowance of `spender` over the `owner` s tokens.
     *
     * This internal function is equivalent to `approve`, and can be used to
     * e.g. set automatic allowances for certain subsystems, etc.
     *
     * Emits an {Approval} event.
     *
     * Requirements:
     *
     * - `owner` cannot be the zero address.
     * - `spender` cannot be the zero address.
     */
    function _approve(address owner, address spender, uint256 amount) internal virtual {
        require(owner != address(0), "ERC20: approve from the zero address");
        require(spender != address(0), "ERC20: approve to the zero address");

        _allowances[owner][spender] = amount;
        emit Approval(owner, spender, amount);
    }

    /**
     * @dev Hook that is called before any transfer of tokens. This includes
     * minting and burning.
     *
     * Calling conditions:
     *
     * - when `from` and `to` are both non-zero, `amount` of ``from``'s tokens
     * will be to transferred to `to`.
     * - when `from` is zero, `amount` tokens will be minted for `to`.
     * - when `to` is zero, `amount` of ``from``'s tokens will be burned.
     * - `from` and `to` are never both zero.
     *
     * To learn more about hooks, head to xref:ROOT:extending-contracts.adoc#using-hooks[Using Hooks].
     */
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual {}
}

/**
 * @dev Extension of {ERC20} that allows token holders to destroy both their own
 * tokens and those that they have an allowance for, in a way that can be
 * recognized off-chain (via event analysis).
 */
abstract contract ERC20Burnable is Context, ERC20 {
    using SafeMath for uint256;

    /**
     * @dev Destroys `amount` tokens from the caller.
     *
     * See {ERC20-_burn}.
     */
    function burn(uint256 amount) public virtual {
        _burn(_msgSender(), amount);
    }

    /**
     * @dev Destroys `amount` tokens from `account`, deducting from the caller's
     * allowance.
     *
     * See {ERC20-_burn} and {ERC20-allowance}.
     *
     * Requirements:
     *
     * - the caller must have allowance for ``accounts``'s tokens of at least
     * `amount`.
     */
    function burnFrom(address account, uint256 amount) public virtual {
        uint256 decreasedAllowance = allowance(account, _msgSender()).sub(amount, "ERC20: burn amount exceeds allowance");

        _approve(account, _msgSender(), decreasedAllowance);
        _burn(account, amount);
    }
}

/**
 * @dev Wrappers over Solidity's arithmetic operations with added overflow
 * checks.
 *
 * Arithmetic operations in Solidity wrap on overflow. This can easily result
 * in bugs, because programmers usually assume that an overflow raises an
 * error, which is the standard behavior in high level programming languages.
 * `SafeMath` restores this intuition by reverting the transaction when an
 * operation overflows.
 *
 * Using this library instead of the unchecked operations eliminates an entire
 * class of bugs, so it's recommended to use it always.
 */
library SafeMath {
    /**
     * @dev Returns the addition of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `+` operator.
     *
     * Requirements:
     *
     * - Addition cannot overflow.
     */
    function add(uint256 a, uint256 b) internal pure returns (uint256) {
        uint256 c = a + b;
        require(c >= a, "SafeMath: addition overflow");

        return c;
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
        return sub(a, b, "SafeMath: subtraction overflow");
    }

    /**
     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
     * overflow (when the result is negative).
     *
     * Counterpart to Solidity's `-` operator.
     *
     * Requirements:
     *
     * - Subtraction cannot overflow.
     */
    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b <= a, errorMessage);
        uint256 c = a - b;

        return c;
    }

    /**
     * @dev Returns the multiplication of two unsigned integers, reverting on
     * overflow.
     *
     * Counterpart to Solidity's `*` operator.
     *
     * Requirements:
     *
     * - Multiplication cannot overflow.
     */
    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
        // benefit is lost if 'b' is also tested.
        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
        if (a == 0) {
            return 0;
        }

        uint256 c = a * b;
        require(c / a == b, "SafeMath: multiplication overflow");

        return c;
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b) internal pure returns (uint256) {
        return div(a, b, "SafeMath: division by zero");
    }

    /**
     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
     * division by zero. The result is rounded towards zero.
     *
     * Counterpart to Solidity's `/` operator. Note: this function uses a
     * `revert` opcode (which leaves remaining gas untouched) while Solidity
     * uses an invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b > 0, errorMessage);
        uint256 c = a / b;
        // assert(a == b * c + a % b); // There is no case in which this doesn't hold

        return c;
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
        return mod(a, b, "SafeMath: modulo by zero");
    }

    /**
     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
     * Reverts with custom message when dividing by zero.
     *
     * Counterpart to Solidity's `%` operator. This function uses a `revert`
     * opcode (which leaves remaining gas untouched) while Solidity uses an
     * invalid opcode to revert (consuming all remaining gas).
     *
     * Requirements:
     *
     * - The divisor cannot be zero.
     */
    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
        require(b != 0, errorMessage);
        return a % b;
    }
}

contract ProassetzToken is ERC20, ERC20Burnable, Blacklistable, Pausable {
    constructor() public ERC20("Proassetz Token", "PROFY", 1000000000 * (10 ** uint256(decimals()))) {
        _mint(0x80D8BAc9a6901698b3749Fe336bBd1385C1f98f2, 100000000 * (10 ** uint256(decimals())));
        transferOwnership(0xfb99F8aE9b70A0C8Cd96aE665BBaf85A7E01a2ef);
    }

    function mint(address account, uint256 amount) public virtual onlyOwner {
        require(ERC20.totalSupply() + amount <= cap(), "ERC20Capped: cap exceeded");
        _mint(account, amount);
    }

    function pause() public virtual onlyOwner {
        _pause();
    }

    function unpause() public virtual onlyOwner {
        _unpause();
    }
    
    function _beforeTokenTransfer(address from, address to, uint256 amount) internal virtual override {
        super._beforeTokenTransfer(from, to, amount);

        require(!isBlacklisted(from), "ERC20WithSafeTransfer: invalid sender");
        require(!isBlacklisted(to), "ERC20WithSafeTransfer: invalid recipient");
        require(!paused(), "ERC20Pausable: token transfer while paused");
    }
}


// File contracts/tatum/TatumTron721.sol

pragma solidity ^0.5.0;
pragma experimental ABIEncoderV2;
///**
// * @dev Wrappers over Solidity's arithmetic operations with added overflow
// * checks.
// *
// * Arithmetic operations in Solidity wrap on overflow. This can easily result
// * in bugs, because programmers usually assume that an overflow raises an
// * error, which is the standard behavior in high level programming languages.
// * `SafeMath` restores this intuition by reverting the transaction when an
// * operation overflows.
// *
// * Using this library instead of the unchecked operations eliminates an entire
// * class of bugs, so it's recommended to use it always.
// */
//library SafeMath {
//    /**
//     * @dev Returns the addition of two unsigned integers, reverting on
//     * overflow.
//     *
//     * Counterpart to Solidity's `+` operator.
//     *
//     * Requirements:
//     * - Addition cannot overflow.
//     */
//    function add(uint256 a, uint256 b) internal pure returns (uint256) {
//        uint256 c = a + b;
//        require(c >= a, "SafeMath: addition overflow");
//
//        return c;
//    }
//
//    /**
//     * @dev Returns the subtraction of two unsigned integers, reverting on
//     * overflow (when the result is negative).
//     *
//     * Counterpart to Solidity's `-` operator.
//     *
//     * Requirements:
//     * - Subtraction cannot overflow.
//     */
//    function sub(uint256 a, uint256 b) internal pure returns (uint256) {
//        return sub(a, b, "SafeMath: subtraction overflow");
//    }
//
//    /**
//     * @dev Returns the subtraction of two unsigned integers, reverting with custom message on
//     * overflow (when the result is negative).
//     *
//     * Counterpart to Solidity's `-` operator.
//     *
//     * Requirements:
//     * - Subtraction cannot overflow.
//     *
//     * _Available since v2.4.0._
//     */
//    function sub(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
//        require(b <= a, errorMessage);
//        uint256 c = a - b;
//
//        return c;
//    }
//
//    /**
//     * @dev Returns the multiplication of two unsigned integers, reverting on
//     * overflow.
//     *
//     * Counterpart to Solidity's `*` operator.
//     *
//     * Requirements:
//     * - Multiplication cannot overflow.
//     */
//    function mul(uint256 a, uint256 b) internal pure returns (uint256) {
//        // Gas optimization: this is cheaper than requiring 'a' not being zero, but the
//        // benefit is lost if 'b' is also tested.
//        // See: https://github.com/OpenZeppelin/openzeppelin-contracts/pull/522
//        if (a == 0) {
//            return 0;
//        }
//
//        uint256 c = a * b;
//        require(c / a == b, "SafeMath: multiplication overflow");
//
//        return c;
//    }
//
//    /**
//     * @dev Returns the integer division of two unsigned integers. Reverts on
//     * division by zero. The result is rounded towards zero.
//     *
//     * Counterpart to Solidity's `/` operator. Note: this function uses a
//     * `revert` opcode (which leaves remaining gas untouched) while Solidity
//     * uses an invalid opcode to revert (consuming all remaining gas).
//     *
//     * Requirements:
//     * - The divisor cannot be zero.
//     */
//    function div(uint256 a, uint256 b) internal pure returns (uint256) {
//        return div(a, b, "SafeMath: division by zero");
//    }
//
//    /**
//     * @dev Returns the integer division of two unsigned integers. Reverts with custom message on
//     * division by zero. The result is rounded towards zero.
//     *
//     * Counterpart to Solidity's `/` operator. Note: this function uses a
//     * `revert` opcode (which leaves remaining gas untouched) while Solidity
//     * uses an invalid opcode to revert (consuming all remaining gas).
//     *
//     * Requirements:
//     * - The divisor cannot be zero.
//     *
//     * _Available since v2.4.0._
//     */
//    function div(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
//        // Solidity only automatically asserts when dividing by 0
//        require(b > 0, errorMessage);
//        uint256 c = a / b;
//        // assert(a == b * c + a % b); // There is no case in which this doesn't hold
//
//        return c;
//    }
//
//    /**
//     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
//     * Reverts when dividing by zero.
//     *
//     * Counterpart to Solidity's `%` operator. This function uses a `revert`
//     * opcode (which leaves remaining gas untouched) while Solidity uses an
//     * invalid opcode to revert (consuming all remaining gas).
//     *
//     * Requirements:
//     * - The divisor cannot be zero.
//     */
//    function mod(uint256 a, uint256 b) internal pure returns (uint256) {
//        return mod(a, b, "SafeMath: modulo by zero");
//    }
//
//    /**
//     * @dev Returns the remainder of dividing two unsigned integers. (unsigned integer modulo),
//     * Reverts with custom message when dividing by zero.
//     *
//     * Counterpart to Solidity's `%` operator. This function uses a `revert`
//     * opcode (which leaves remaining gas untouched) while Solidity uses an
//     * invalid opcode to revert (consuming all remaining gas).
//     *
//     * Requirements:
//     * - The divisor cannot be zero.
//     *
//     * _Available since v2.4.0._
//     */
//    function mod(uint256 a, uint256 b, string memory errorMessage) internal pure returns (uint256) {
//        require(b != 0, errorMessage);
//        return a % b;
//    }
//}
//
///*
// * @dev Provides information about the current execution context, including the
// * sender of the transaction and its data. While these are generally available
// * via msg.sender and msg.data, they should not be accessed in such a direct
// * manner, since when dealing with GSN meta-transactions the account sending and
// * paying for execution may not be the actual sender (as far as an application
// * is concerned).
// *
// * This contract is only required for intermediate, library-like contracts.
// */
//contract Context {
//    // Empty internal constructor, to prevent people from mistakenly deploying
//    // an instance of this contract, which should be used via inheritance.
//    constructor () internal { }
//    // solhint-disable-previous-line no-empty-blocks
//
//    function _msgSender() internal view returns (address payable) {
//        return msg.sender;
//    }
//
//    function _msgData() internal view returns (bytes memory) {
//        this; // silence state mutability warning without generating bytecode - see https://github.com/ethereum/solidity/issues/2691
//        return msg.data;
//    }
//}
//
///**
// * @title Roles
// * @dev Library for managing addresses assigned to a Role.
// */
//library Roles {
//    struct Role {
//        mapping (address => bool) bearer;
//    }
//
//    /**
//     * @dev Give an account access to this role.
//     */
//    function add(Role storage role, address account) internal {
//        require(!has(role, account), "Roles: account already has role");
//        role.bearer[account] = true;
//    }
//
//    /**
//     * @dev Remove an account's access to this role.
//     */
//    function remove(Role storage role, address account) internal {
//        require(has(role, account), "Roles: account does not have role");
//        role.bearer[account] = false;
//    }
//
//    /**
//     * @dev Check if an account has this role.
//     * @return bool
//     */
//    function has(Role storage role, address account) internal view returns (bool) {
//        require(account != address(0), "Roles: account is the zero address");
//        return role.bearer[account];
//    }
//}
//pragma solidity ^0.5.5;
//
///**
// * @dev Collection of functions related to the address type
// */
//library Address {
//    /**
//     * @dev Converts an `address` into `address payable`. Note that this is
//     * simply a type cast: the actual underlying value is not changed.
//     *
//     * _Available since v2.4.0._
//     */
//    function toPayable(address account) internal pure returns (address payable) {
//        return address(uint160(account));
//    }
//
//    /**
//     * @dev Replacement for Solidity's `transfer`: sends `amount` wei to
//     * `recipient`, forwarding all available gas and reverting on errors.
//     *
//     * https://diligence.consensys.net/posts/2019/09/stop-using-soliditys-transfer-now/[Learn more].
//     *
//     * IMPORTANT: because control is transferred to `recipient`, care must be
//     * taken to not create reentrancy vulnerabilities. Consider using
//     * {ReentrancyGuard} or the
//     * https://solidity.readthedocs.io/en/v0.5.11/security-considerations.html#use-the-checks-effects-interactions-pattern[checks-effects-interactions pattern].
//     *
//     * _Available since v2.4.0._
//     */
//    function sendValue(address payable recipient, uint256 amount) internal {
//        require(address(this).balance >= amount, "Address: insufficient balance");
//
//        // solhint-disable-next-line avoid-call-value
//        (bool success, ) = recipient.call.value(amount)("");
//        require(success, "Address: unable to send value, recipient may have reverted");
//    }
//}
//
//
///**
// * @title Counters
// * @author Matt Condon (@shrugs)
// * @dev Provides counters that can only be incremented or decremented by one. This can be used e.g. to track the number
// * of elements in a mapping, issuing TRC721 ids, or counting request ids.
// *
// * Include with `using Counters for Counters.Counter;`
// * Since it is not possible to overflow a 256 bit integer with increments of one, `increment` can skip the {SafeMath}
// * overflow check, thereby saving gas. This does assume however correct usage, in that the underlying `_value` is never
// * directly accessed.
// */
//library Counters {
//    using SafeMath for uint256;
//
//    struct Counter {
//        // This variable should never be directly accessed by users of the library: interactions must be restricted to
//        // the library's function. As of Solidity v0.5.2, this cannot be enforced, though there is a proposal to add
//        // this feature: see https://github.com/ethereum/solidity/issues/4637
//        uint256 _value; // default: 0
//    }
//
//    function current(Counter storage counter) internal view returns (uint256) {
//        return counter._value;
//    }
//
//    function increment(Counter storage counter) internal {
//        // The {SafeMath} overflow check can be skipped here, see the comment at the top
//        counter._value += 1;
//    }
//
//    function decrement(Counter storage counter) internal {
//        counter._value = counter._value.sub(1);
//    }
//}
//
//
//contract MinterRole is Context {
//    using Roles for Roles.Role;
//
//    event MinterAdded(address indexed account);
//    event MinterRemoved(address indexed account);
//
//    Roles.Role private _minters;
//
//    constructor () internal {
//        _addMinter(_msgSender());
//    }
//
//    modifier onlyMinter() {
//        require(isMinter(_msgSender()), "MinterRole: caller does not have the Minter role");
//        _;
//    }
//
//    function isMinter(address account) public view returns (bool) {
//        return _minters.has(account);
//    }
//
//    function addMinter(address account) public onlyMinter {
//        _addMinter(account);
//    }
//
//    function renounceMinter() public {
//        _removeMinter(_msgSender());
//    }
//
//    function _addMinter(address account) internal {
//        _minters.add(account);
//        emit MinterAdded(account);
//    }
//
//    function _removeMinter(address account) internal {
//        _minters.remove(account);
//        emit MinterRemoved(account);
//    }
//}
//
///**
// * @dev Interface of the TRC165 standard.
// *
// * Implementers can declare support of contract interfaces, which can then be
// * queried by others ({TRC165Checker}).
// *
// * For an implementation, see {TRC165}.
// */
//interface ITRC165 {
//    /**
//     * @dev Returns true if this contract implements the interface defined by
//     * `interfaceId`.
//     *
//     * This function call must use less than 30 000 gas.
//     */
//    function supportsInterface(bytes4 interfaceId) external view returns (bool);
//}
//
//
///**
// * @dev Required interface of an TRC721 compliant contract.
// */
//contract ITRC721 is ITRC165 {
//    event Transfer(address indexed from, address indexed to, uint256 indexed tokenId);
//    event Approval(address indexed owner, address indexed approved, uint256 indexed tokenId);
//    event ApprovalForAll(address indexed owner, address indexed operator, bool approved);
//
//    /**
//     * @dev Returns the number of NFTs in `owner`'s account.
//     */
//    function balanceOf(address owner) public view returns (uint256 balance);
//
//    /**
//     * @dev Returns the owner of the NFT specified by `tokenId`.
//     */
//    function ownerOf(uint256 tokenId) public view returns (address owner);
//
//    /**
//     * @dev Transfers a specific NFT (`tokenId`) from one account (`from`) to
//     * another (`to`).
//     *
//     *
//     *
//     * Requirements:
//     * - `from`, `to` cannot be zero.
//     * - `tokenId` must be owned by `from`.
//     * - If the caller is not `from`, it must be have been allowed to move this
//     * NFT by either {approve} or {setApprovalForAll}.
//     */
//    function safeTransferFrom(address from, address to, uint256 tokenId) public;
//    /**
//     * @dev Transfers a specific NFT (`tokenId`) from one account (`from`) to
//     * another (`to`).
//     *
//     * Requirements:
//     * - If the caller is not `from`, it must be approved to move this NFT by
//     * either {approve} or {setApprovalForAll}.
//     */
//    function transferFrom(address from, address to, uint256 tokenId) public;
//    function approve(address to, uint256 tokenId) public;
//    function getApproved(uint256 tokenId) public view returns (address operator);
//
//    function setApprovalForAll(address operator, bool _approved) public;
//    function isApprovedForAll(address owner, address operator) public view returns (bool);
//
//
//    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory data) public;
//}
//
//
///**
// * @title TRC-721 Non-Fungible Token Standard, optional metadata extension
// */
//contract ITRC721Metadata is ITRC721 {
//    function name() external view returns (string memory);
//    function symbol() external view returns (string memory);
//    function tokenURI(uint256 tokenId) external view returns (string memory);
//}
//
///**
// * @title TRC721 token receiver interface
// * @dev Interface for any contract that wants to support safeTransfers
// * from TRC721 asset contracts.
// */
//contract ITRC721Receiver {
//    /**
//     * @notice Handle the receipt of an NFT
//     * @dev The TRC721 smart contract calls this function on the recipient
//     * after a {ITRC721-safeTransferFrom}. This function MUST return the function selector,
//     * otherwise the caller will revert the transaction. The selector to be
//     * returned can be obtained as `this.onTRC721Received.selector`. This
//     * function MAY throw to revert and reject the transfer.
//     * Note: the TRC721 contract address is always the message sender.
//     * @param operator The address which called `safeTransferFrom` function
//     * @param from The address which previously owned the token
//     * @param tokenId The NFT identifier which is being transferred
//     * @param data Additional data with no specified format
//     * @return bytes4 `bytes4(keccak256("onTRC721Received(address,address,uint256,bytes)"))`
//     */
//    function onTRC721Received(address operator, address from, uint256 tokenId, bytes memory data)
//    public returns (bytes4);
//}
//
//
///**
// * @dev Implementation of the {ITRC165} interface.
// *
// * Contracts may inherit from this and call {_registerInterface} to declare
// * their support of an interface.
// */
//contract TRC165 is ITRC165 {
//    /*
//     * bytes4(keccak256('supportsInterface(bytes4)')) == 0x01ffc9a7
//     */
//    bytes4 private constant _INTERFACE_ID_TRC165 = 0x01ffc9a7;
//
//    /**
//     * @dev Mapping of interface ids to whether or not it's supported.
//     */
//    mapping(bytes4 => bool) private _supportedInterfaces;
//
//    constructor () internal {
//        // Derived contracts need only register support for their own interfaces,
//        // we register support for TRC165 itself here
//        _registerInterface(_INTERFACE_ID_TRC165);
//    }
//
//    /**
//     * @dev See {ITRC165-supportsInterface}.
//     *
//     * Time complexity O(1), guaranteed to always use less than 30 000 gas.
//     */
//    function supportsInterface(bytes4 interfaceId) external view returns (bool) {
//        return _supportedInterfaces[interfaceId];
//    }
//
//    /**
//     * @dev Registers the contract as an implementer of the interface defined by
//     * `interfaceId`. Support of the actual TRC165 interface is automatic and
//     * registering its interface id is not required.
//     *
//     * See {ITRC165-supportsInterface}.
//     *
//     * Requirements:
//     *
//     * - `interfaceId` cannot be the TRC165 invalid interface (`0xffffffff`).
//     */
//    function _registerInterface(bytes4 interfaceId) internal {
//        require(interfaceId != 0xffffffff, "TRC165: invalid interface id");
//        _supportedInterfaces[interfaceId] = true;
//    }
//}
//
//
///**
// * @title TRC721 Non-Fungible Token Standard basic implementation
// */
//contract TRC721 is Context, TRC165, ITRC721, MinterRole {
//    using SafeMath for uint256;
//    using Address for address;
//    using Counters for Counters.Counter;
//
//    // Equals to `bytes4(keccak256("onTRC721Received(address,address,uint256,bytes)"))`
//    // which can be also obtained as `ITRC721Receiver(0).onTRC721Received.selector`
//    //
//    // NOTE: TRC721 uses 0x150b7a02, TRC721 uses 0x5175f878.
//    bytes4 private constant _TRC721_RECEIVED = 0x5175f878;
//
//    // Mapping from token ID to owner
//    mapping (uint256 => address) private _tokenOwner;
//
//    // Mapping from token ID to approved address
//    mapping (uint256 => address) private _tokenApprovals;
//
//    // Mapping from owner to number of owned token
//    mapping (address => Counters.Counter) private _ownedTokensCount;
//
//    // Mapping from owner to operator approvals
//    mapping (address => mapping (address => bool)) private _operatorApprovals;
//
//    /*
//     *     bytes4(keccak256('balanceOf(address)')) == 0x70a08231
//     *     bytes4(keccak256('ownerOf(uint256)')) == 0x6352211e
//     *     bytes4(keccak256('approve(address,uint256)')) == 0x095ea7b3
//     *     bytes4(keccak256('getApproved(uint256)')) == 0x081812fc
//     *     bytes4(keccak256('setApprovalForAll(address,bool)')) == 0xa22cb465
//     *     bytes4(keccak256('isApprovedForAll(address,address)')) == 0xe985e9c5
//     *     bytes4(keccak256('transferFrom(address,address,uint256)')) == 0x23b872dd
//     *     bytes4(keccak256('safeTransferFrom(address,address,uint256)')) == 0x42842e0e
//     *     bytes4(keccak256('safeTransferFrom(address,address,uint256,bytes)')) == 0xb88d4fde
//     *
//     *     => 0x70a08231 ^ 0x6352211e ^ 0x095ea7b3 ^ 0x081812fc ^
//     *        0xa22cb465 ^ 0xe985e9c ^ 0x23b872dd ^ 0x42842e0e ^ 0xb88d4fde == 0x80ac58cd
//     */
//    bytes4 private constant _INTERFACE_ID_TRC721 = 0x80ac58cd;
//
//    constructor () public {
//        // register the supported interfaces to conform to TRC721 via TRC165
//        _registerInterface(_INTERFACE_ID_TRC721);
//    }
//
//    /**
//     * @dev Gets the balance of the specified address.
//     * @param owner address to query the balance of
//     * @return uint256 representing the amount owned by the passed address
//     */
//    function balanceOf(address owner) public view returns (uint256) {
//        require(owner != address(0), "TRC721: balance query for the zero address");
//
//        return _ownedTokensCount[owner].current();
//    }
//
//    /**
//     * @dev Gets the owner of the specified token ID.
//     * @param tokenId uint256 ID of the token to query the owner of
//     * @return address currently marked as the owner of the given token ID
//     */
//    function ownerOf(uint256 tokenId) public view returns (address) {
//        address owner = _tokenOwner[tokenId];
//        require(owner != address(0), "TRC721: owner query for nonexistent token");
//
//        return owner;
//    }
//
//    /**
//     * @dev Approves another address to transfer the given token ID
//     * The zero address indicates there is no approved address.
//     * There can only be one approved address per token at a given time.
//     * Can only be called by the token owner or an approved operator.
//     * @param to address to be approved for the given token ID
//     * @param tokenId uint256 ID of the token to be approved
//     */
//    function approve(address to, uint256 tokenId) public {
//        address owner = ownerOf(tokenId);
//        require(to != owner, "TRC721: approval to current owner");
//
//        require(_msgSender() == owner || isApprovedForAll(owner, _msgSender()),
//            "TRC721: approve caller is not owner nor approved for all"
//        );
//
//        _tokenApprovals[tokenId] = to;
//        emit Approval(owner, to, tokenId);
//    }
//
//    /**
//     * @dev Gets the approved address for a token ID, or zero if no address set
//     * Reverts if the token ID does not exist.
//     * @param tokenId uint256 ID of the token to query the approval of
//     * @return address currently approved for the given token ID
//     */
//    function getApproved(uint256 tokenId) public view returns (address) {
//        require(_exists(tokenId), "TRC721: approved query for nonexistent token");
//
//        return _tokenApprovals[tokenId];
//    }
//
//    /**
//     * @dev Sets or unsets the approval of a given operator
//     * An operator is allowed to transfer all tokens of the sender on their behalf.
//     * @param to operator address to set the approval
//     * @param approved representing the status of the approval to be set
//     */
//    function setApprovalForAll(address to, bool approved) public {
//        require(to != _msgSender(), "TRC721: approve to caller");
//
//        _operatorApprovals[_msgSender()][to] = approved;
//        emit ApprovalForAll(_msgSender(), to, approved);
//    }
//
//    /**
//     * @dev Tells whether an operator is approved by a given owner.
//     * @param owner owner address which you want to query the approval of
//     * @param operator operator address which you want to query the approval of
//     * @return bool whether the given operator is approved by the given owner
//     */
//    function isApprovedForAll(address owner, address operator) public view returns (bool) {
//        return _operatorApprovals[owner][operator];
//    }
//
//    /**
//     * @dev Transfers the ownership of a given token ID to another address.
//     * Usage of this method is discouraged, use {safeTransferFrom} whenever possible.
//     * Requires the msg.sender to be the owner, approved, or operator.
//     * @param from current owner of the token
//     * @param to address to receive the ownership of the given token ID
//     * @param tokenId uint256 ID of the token to be transferred
//     */
//    function transferFrom(address from, address to, uint256 tokenId) public {
//        //solhint-disable-next-line max-line-length
//        require(_isApprovedOrOwner(_msgSender(), tokenId), "TRC721: transfer caller is not owner nor approved");
//
//        _transferFrom(from, to, tokenId);
//    }
//
//    /**
//     * @dev Safely transfers the ownership of a given token ID to another address
//     * If the target address is a contract, it must implement {ITRC721Receiver-onTRC721Received},
//     * which is called upon a safe transfer, and return the magic value
//     * `bytes4(keccak256("onTRC721Received(address,address,uint256,bytes)"))`; otherwise,
//     * the transfer is reverted.
//     * Requires the msg.sender to be the owner, approved, or operator
//     * @param from current owner of the token
//     * @param to address to receive the ownership of the given token ID
//     * @param tokenId uint256 ID of the token to be transferred
//     */
//    function safeTransferFrom(address from, address to, uint256 tokenId) public {
//        safeTransferFrom(from, to, tokenId, "");
//    }
//
//    /**
//     * @dev Safely transfers the ownership of a given token ID to another address
//     * If the target address is a contract, it must implement {ITRC721Receiver-onTRC721Received},
//     * which is called upon a safe transfer, and return the magic value
//     * `bytes4(keccak256("onTRC721Received(address,address,uint256,bytes)"))`; otherwise,
//     * the transfer is reverted.
//     * Requires the _msgSender() to be the owner, approved, or operator
//     * @param from current owner of the token
//     * @param to address to receive the ownership of the given token ID
//     * @param tokenId uint256 ID of the token to be transferred
//     * @param _data bytes data to send along with a safe transfer check
//     */
//    function safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) public {
//        require(_isApprovedOrOwner(_msgSender(), tokenId), "TRC721: transfer caller is not owner nor approved");
//        _safeTransferFrom(from, to, tokenId, _data);
//    }
//
//    /**
//     * @dev Safely transfers the ownership of a given token ID to another address
//     * If the target address is a contract, it must implement `onTRC721Received`,
//     * which is called upon a safe transfer, and return the magic value
//     * `bytes4(keccak256("onTRC721Received(address,address,uint256,bytes)"))`; otherwise,
//     * the transfer is reverted.
//     * Requires the msg.sender to be the owner, approved, or operator
//     * @param from current owner of the token
//     * @param to address to receive the ownership of the given token ID
//     * @param tokenId uint256 ID of the token to be transferred
//     * @param _data bytes data to send along with a safe transfer check
//     */
//    function _safeTransferFrom(address from, address to, uint256 tokenId, bytes memory _data) internal {
//        _transferFrom(from, to, tokenId);
//        require(_checkOnTRC721Received(from, to, tokenId, _data), "TRC721: transfer to non TRC721Receiver implementer");
//    }
//
//    /**
//     * @dev Returns whether the specified token exists.
//     * @param tokenId uint256 ID of the token to query the existence of
//     * @return bool whether the token exists
//     */
//    function _exists(uint256 tokenId) internal view returns (bool) {
//        address owner = _tokenOwner[tokenId];
//        return owner != address(0);
//    }
//
//    /**
//     * @dev Returns whether the given spender can transfer a given token ID.
//     * @param spender address of the spender to query
//     * @param tokenId uint256 ID of the token to be transferred
//     * @return bool whether the msg.sender is approved for the given token ID,
//     * is an operator of the owner, or is the owner of the token
//     */
//    function _isApprovedOrOwner(address spender, uint256 tokenId) internal view returns (bool) {
//        require(_exists(tokenId), "TRC721: operator query for nonexistent token");
//        address owner = ownerOf(tokenId);
//        return (spender == owner || getApproved(tokenId) == spender || isApprovedForAll(owner, spender));
//    }
//
//    /**
//     * @dev Internal function to safely mint a new token.
//     * Reverts if the given token ID already exists.
//     * If the target address is a contract, it must implement `onTRC721Received`,
//     * which is called upon a safe transfer, and return the magic value
//     * `bytes4(keccak256("onTRC721Received(address,address,uint256,bytes)"))`; otherwise,
//     * the transfer is reverted.
//     * @param to The address that will own the minted token
//     * @param tokenId uint256 ID of the token to be minted
//     */
//    function _safeMint(address to, uint256 tokenId) internal {
//        _safeMint(to, tokenId, "");
//    }
//
//    /**
//     * @dev Internal function to safely mint a new token.
//     * Reverts if the given token ID already exists.
//     * If the target address is a contract, it must implement `onTRC721Received`,
//     * which is called upon a safe transfer, and return the magic value
//     * `bytes4(keccak256("onTRC721Received(address,address,uint256,bytes)"))`; otherwise,
//     * the transfer is reverted.
//     * @param to The address that will own the minted token
//     * @param tokenId uint256 ID of the token to be minted
//     * @param _data bytes data to send along with a safe transfer check
//     */
//    function _safeMint(address to, uint256 tokenId, bytes memory _data) internal {
//        _mint(to, tokenId);
//        require(_checkOnTRC721Received(address(0), to, tokenId, _data), "TRC721: transfer to non TRC721Receiver implementer");
//    }
//
//    /**
//     * @dev Internal function to mint a new token.
//     * Reverts if the given token ID already exists.
//     * @param to The address that will own the minted token
//     * @param tokenId uint256 ID of the token to be minted
//     */
//    function _mint(address to, uint256 tokenId) internal onlyMinter {
//        require(to != address(0), "TRC721: mint to the zero address");
//        require(!_exists(tokenId), "TRC721: token already minted");
//
//        _tokenOwner[tokenId] = to;
//        _ownedTokensCount[to].increment();
//
//        emit Transfer(address(0), to, tokenId);
//    }
//
//    /**
//     * @dev Internal function to burn a specific token.
//     * Reverts if the token does not exist.
//     * Deprecated, use {_burn} instead.
//     * @param owner owner of the token to burn
//     * @param tokenId uint256 ID of the token being burned
//     */
//    function _burn(address owner, uint256 tokenId) internal {
//        require(ownerOf(tokenId) == owner, "TRC721: burn of token that is not own");
//
//        _clearApproval(tokenId);
//
//        _ownedTokensCount[owner].decrement();
//        _tokenOwner[tokenId] = address(0);
//
//        emit Transfer(owner, address(0), tokenId);
//    }
//
//    /**
//     * @dev Internal function to burn a specific token.
//     * Reverts if the token does not exist.
//     * @param tokenId uint256 ID of the token being burned
//     */
//    function _burn(uint256 tokenId) internal {
//        _burn(ownerOf(tokenId), tokenId);
//    }
//
//    /**
//     * @dev Internal function to transfer ownership of a given token ID to another address.
//     * As opposed to {transferFrom}, this imposes no restrictions on msg.sender.
//     * @param from current owner of the token
//     * @param to address to receive the ownership of the given token ID
//     * @param tokenId uint256 ID of the token to be transferred
//     */
//    function _transferFrom(address from, address to, uint256 tokenId) internal {
//        require(ownerOf(tokenId) == from, "TRC721: transfer of token that is not own");
//        require(to != address(0), "TRC721: transfer to the zero address");
//
//        _clearApproval(tokenId);
//
//        _ownedTokensCount[from].decrement();
//        _ownedTokensCount[to].increment();
//
//        _tokenOwner[tokenId] = to;
//
//        emit Transfer(from, to, tokenId);
//    }
//
//    /**
//     * @dev Internal function to invoke {ITRC721Receiver-onTRC721Received} on a target address.
//     * The call is not executed if the target address is not a contract.
//     *
//     * This is an internal detail of the `TRC721` contract and its use is deprecated.
//     * @param from address representing the previous owner of the given token ID
//     * @param to target address that will receive the tokens
//     * @param tokenId uint256 ID of the token to be transferred
//     * @param _data bytes optional data to send along with the call
//     * @return bool whether the call correctly returned the expected magic value
//     */
//    function _checkOnTRC721Received(address from, address to, uint256 tokenId, bytes memory _data)
//    internal returns (bool)
//    {
//        if (!to.isContract) {
//            return true;
//        }
//        // solhint-disable-next-line avoid-low-level-calls
//        (bool success, bytes memory returndata) = to.call(abi.encodeWithSelector(
//                ITRC721Receiver(to).onTRC721Received.selector,
//                _msgSender(),
//                from,
//                tokenId,
//                _data
//            ));
//        if (!success) {
//            if (returndata.length > 0) {
//                // solhint-disable-next-line no-inline-assembly
//                assembly {
//                    let returndata_size := mload(returndata)
//                    revert(add(32, returndata), returndata_size)
//                }
//            } else {
//                revert("TRC721: transfer to non TRC721Receiver implementer");
//            }
//        } else {
//            bytes4 retval = abi.decode(returndata, (bytes4));
//            return (retval == _TRC721_RECEIVED);
//        }
//    }
//
//    /**
//     * @dev Private function to clear current approval of a given token ID.
//     * @param tokenId uint256 ID of the token to be transferred
//     */
//    function _clearApproval(uint256 tokenId) private {
//        if (_tokenApprovals[tokenId] != address(0)) {
//            _tokenApprovals[tokenId] = address(0);
//        }
//    }
//}
//
//
//contract TRC721Metadata is Context, TRC165, TRC721, ITRC721Metadata {
//    // Token name
//    string private _name;
//
//    // Token symbol
//    string private _symbol;
//
//    // Base URI
//    string private _baseURI;
//
//    // Optional mapping for token URIs
//    mapping(uint256 => string) private _tokenURIs;
//
//    /*
//     *     bytes4(keccak256('name()')) == 0x06fdde03
//     *     bytes4(keccak256('symbol()')) == 0x95d89b41
//     *     bytes4(keccak256('tokenURI(uint256)')) == 0xc87b56dd
//     *
//     *     => 0x06fdde03 ^ 0x95d89b41 ^ 0xc87b56dd == 0x5b5e139f
//     */
//    bytes4 private constant _INTERFACE_ID_TRC721_METADATA = 0x5b5e139f;
//
//    /**
//     * @dev Constructor function
//     */
//    constructor (string memory name, string memory symbol) public {
//        _name = name;
//        _symbol = symbol;
//
//        // register the supported interfaces to conform to TRC721 via TRC165
//        _registerInterface(_INTERFACE_ID_TRC721_METADATA);
//    }
//
//    /**
//     * @dev Gets the token name.
//     * @return string representing the token name
//     */
//    function name() external view returns (string memory) {
//        return _name;
//    }
//
//    /**
//     * @dev Gets the token symbol.
//     * @return string representing the token symbol
//     */
//    function symbol() external view returns (string memory) {
//        return _symbol;
//    }
//
//    /**
//     * @dev Returns the URI for a given token ID. May return an empty string.
//     *
//     * If the token's URI is non-empty and a base URI was set (via
//     * {_setBaseURI}), it will be added to the token ID's URI as a prefix.
//     *
//     * Reverts if the token ID does not exist.
//     */
//    function tokenURI(uint256 tokenId) external view returns (string memory) {
//        require(_exists(tokenId), "TRC721Metadata: URI query for nonexistent token");
//
//        string memory _tokenURI = _tokenURIs[tokenId];
//
//        // Even if there is a base URI, it is only appended to non-empty token-specific URIs
//        if (bytes(_tokenURI).length == 0) {
//            return "";
//        } else {
//            // abi.encodePacked is being used to concatenate strings
//            return string(abi.encodePacked(_baseURI, _tokenURI));
//        }
//    }
//
//    /**
//     * @dev Internal function to set the token URI for a given token.
//     *
//     * Reverts if the token ID does not exist.
//     *
//     * TIP: if all token IDs share a prefix (e.g. if your URIs look like
//     * `http://api.myproject.com/token/<id>`), use {_setBaseURI} to store
//     * it and save gas.
//     */
//    function _setTokenURI(uint256 tokenId, string memory _tokenURI) internal {
//        require(_exists(tokenId), "TRC721Metadata: URI set of nonexistent token");
//        _tokenURIs[tokenId] = _tokenURI;
//    }
//
//    /**
//     * @dev Internal function to set the base URI for all token IDs. It is
//     * automatically added as a prefix to the value returned in {tokenURI}.
//     *
//     * _Available since v2.5.0._
//     */
//    function _setBaseURI(string memory baseURI) internal {
//        _baseURI = baseURI;
//    }
//
//    /**
//    * @dev Returns the base URI set via {_setBaseURI}. This will be
//    * automatically added as a preffix in {tokenURI} to each token's URI, when
//    * they are non-empty.
//    *
//    * _Available since v2.5.0._
//    */
//    function baseURI() external view returns (string memory) {
//        return _baseURI;
//    }
//
//    /**
//     * @dev Internal function to burn a specific token.
//     * Reverts if the token does not exist.
//     * Deprecated, use _burn(uint256) instead.
//     * @param owner owner of the token to burn
//     * @param tokenId uint256 ID of the token being burned by the msg.sender
//     */
//    function _burn(address owner, uint256 tokenId) internal {
//        super._burn(owner, tokenId);
//
//        // Clear metadata (if any)
//        if (bytes(_tokenURIs[tokenId]).length != 0) {
//            delete _tokenURIs[tokenId];
//        }
//    }
//}
//
//
//
///**
// * @title TRC721MetadataMintable
// * @dev TRC721 minting logic with metadata.
// */
//contract TRC721MetadataMintable is TRC721, TRC721Metadata {
//    /**
//     * @dev Function to mint tokens.
//     * @param to The address that will receive the minted tokens.
//     * @param tokenId The token id to mint.
//     * @param tokenURI The token URI of the minted token.
//     * @return A boolean that indicates if the operation was successful.
//     */
//    function mintWithTokenURI(address to, uint256 tokenId, string memory tokenURI) public onlyMinter returns (bool) {
//        _mint(to, tokenId);
//        _setTokenURI(tokenId, tokenURI);
//        return true;
//    }
//}
//
//
///**
// * @title TRC721Mintable
// * @dev TRC721 minting logic.
// */
//contract TRC721Mintable is TRC721 {
//    /**
//     * @dev Function to mint tokens.
//     * @param to The address that will receive the minted token.
//     * @param tokenId The token id to mint.
//     * @return A boolean that indicates if the operation was successful.
//     */
//    function mint(address to, uint256 tokenId) public onlyMinter returns (bool) {
//        _mint(to, tokenId);
//        return true;
//    }
//
//    /**
//     * @dev Function to safely mint tokens.
//     * @param to The address that will receive the minted token.
//     * @param tokenId The token id to mint.
//     * @return A boolean that indicates if the operation was successful.
//     */
//    function safeMint(address to, uint256 tokenId) public onlyMinter returns (bool) {
//        _safeMint(to, tokenId);
//        return true;
//    }
//
//    /**
//     * @dev Function to safely mint tokens.
//     * @param to The address that will receive the minted token.
//     * @param tokenId The token id to mint.
//     * @param _data bytes data to send along with a safe transfer check.
//     * @return A boolean that indicates if the operation was successful.
//     */
//    function safeMint(address to, uint256 tokenId, bytes memory _data) public onlyMinter returns (bool) {
//        _safeMint(to, tokenId, _data);
//        return true;
//    }
//}
//
///**
// * @title TRC-721 Non-Fungible Token Standard, optional enumeration extension
// */
//contract ITRC721Enumerable is ITRC721 {
//    function totalSupply() public view returns (uint256);
//    function tokenOfOwnerByIndex(address owner, uint256 index) public view returns (uint256 tokenId);
//
//    function tokenByIndex(uint256 index) public view returns (uint256);
//}
//
///**
// * @title TRC-721 Non-Fungible Token with optional enumeration extension logic
// */
//contract TRC721Enumerable is Context, TRC165, TRC721, ITRC721Enumerable {
//    // Mapping from owner to list of owned token IDs
//    mapping(address => uint256[]) private _ownedTokens;
//
//    // Mapping from token ID to index of the owner tokens list
//    mapping(uint256 => uint256) private _ownedTokensIndex;
//
//    // Array with all token ids, used for enumeration
//    uint256[] private _allTokens;
//
//    // Mapping from token id to position in the allTokens array
//    mapping(uint256 => uint256) private _allTokensIndex;
//
//    /*
//     *     bytes4(keccak256('totalSupply()')) == 0x18160ddd
//     *     bytes4(keccak256('tokenOfOwnerByIndex(address,uint256)')) == 0x2f745c59
//     *     bytes4(keccak256('tokenByIndex(uint256)')) == 0x4f6ccce7
//     *
//     *     => 0x18160ddd ^ 0x2f745c59 ^ 0x4f6ccce7 == 0x780e9d63
//     */
//    bytes4 private constant _INTERFACE_ID_TRC721_ENUMERABLE = 0x780e9d63;
//
//    /**
//     * @dev Constructor function.
//     */
//    constructor () public {
//        // register the supported interface to conform to TRC721Enumerable via TRC165
//        _registerInterface(_INTERFACE_ID_TRC721_ENUMERABLE);
//    }
//
//    /**
//     * @dev Gets the token ID at a given index of the tokens list of the requested owner.
//     * @param owner address owning the tokens list to be accessed
//     * @param index uint256 representing the index to be accessed of the requested tokens list
//     * @return uint256 token ID at the given index of the tokens list owned by the requested address
//     */
//    function tokenOfOwnerByIndex(address owner, uint256 index) public view returns (uint256) {
//        require(index < balanceOf(owner), "TRC721Enumerable: owner index out of bounds");
//        return _ownedTokens[owner][index];
//    }
//
//    /**
//     * @dev Gets the total amount of tokens stored by the contract.
//     * @return uint256 representing the total amount of tokens
//     */
//    function totalSupply() public view returns (uint256) {
//        return _allTokens.length;
//    }
//
//    /**
//     * @dev Gets the token ID at a given index of all the tokens in this contract
//     * Reverts if the index is greater or equal to the total number of tokens.
//     * @param index uint256 representing the index to be accessed of the tokens list
//     * @return uint256 token ID at the given index of the tokens list
//     */
//    function tokenByIndex(uint256 index) public view returns (uint256) {
//        require(index < totalSupply(), "TRC721Enumerable: global index out of bounds");
//        return _allTokens[index];
//    }
//
//    /**
//     * @dev Internal function to transfer ownership of a given token ID to another address.
//     * As opposed to transferFrom, this imposes no restrictions on msg.sender.
//     * @param from current owner of the token
//     * @param to address to receive the ownership of the given token ID
//     * @param tokenId uint256 ID of the token to be transferred
//     */
//    function _transferFrom(address from, address to, uint256 tokenId) internal {
//        super._transferFrom(from, to, tokenId);
//
//        _removeTokenFromOwnerEnumeration(from, tokenId);
//
//        _addTokenToOwnerEnumeration(to, tokenId);
//    }
//
//    /**
//     * @dev Internal function to mint a new token.
//     * Reverts if the given token ID already exists.
//     * @param to address the beneficiary that will own the minted token
//     * @param tokenId uint256 ID of the token to be minted
//     */
//    function _mint(address to, uint256 tokenId) internal {
//        super._mint(to, tokenId);
//
//        _addTokenToOwnerEnumeration(to, tokenId);
//
//        _addTokenToAllTokensEnumeration(tokenId);
//    }
//
//    /**
//     * @dev Internal function to burn a specific token.
//     * Reverts if the token does not exist.
//     * Deprecated, use {TRC721-_burn} instead.
//     * @param owner owner of the token to burn
//     * @param tokenId uint256 ID of the token being burned
//     */
//    function _burn(address owner, uint256 tokenId) internal {
//        super._burn(owner, tokenId);
//
//        _removeTokenFromOwnerEnumeration(owner, tokenId);
//        // Since tokenId will be deleted, we can clear its slot in _ownedTokensIndex to trigger a gas refund
//        _ownedTokensIndex[tokenId] = 0;
//
//        _removeTokenFromAllTokensEnumeration(tokenId);
//    }
//
//    /**
//     * @dev Gets the list of token IDs of the requested owner.
//     * @param owner address owning the tokens
//     * @return uint256[] List of token IDs owned by the requested address
//     */
//    function _tokensOfOwner(address owner) internal view returns (uint256[] storage) {
//        return _ownedTokens[owner];
//    }
//
//    /**
//     * @dev Private function to add a token to this extension's ownership-tracking data structures.
//     * @param to address representing the new owner of the given token ID
//     * @param tokenId uint256 ID of the token to be added to the tokens list of the given address
//     */
//    function _addTokenToOwnerEnumeration(address to, uint256 tokenId) private {
//        _ownedTokensIndex[tokenId] = _ownedTokens[to].length;
//        _ownedTokens[to].push(tokenId);
//    }
//
//    /**
//     * @dev Private function to add a token to this extension's token tracking data structures.
//     * @param tokenId uint256 ID of the token to be added to the tokens list
//     */
//    function _addTokenToAllTokensEnumeration(uint256 tokenId) private {
//        _allTokensIndex[tokenId] = _allTokens.length;
//        _allTokens.push(tokenId);
//    }
//
//    /**
//     * @dev Private function to remove a token from this extension's ownership-tracking data structures. Note that
//     * while the token is not assigned a new owner, the `_ownedTokensIndex` mapping is _not_ updated: this allows for
//     * gas optimizations e.g. when performing a transfer operation (avoiding double writes).
//     * This has O(1) time complexity, but alters the order of the _ownedTokens array.
//     * @param from address representing the previous owner of the given token ID
//     * @param tokenId uint256 ID of the token to be removed from the tokens list of the given address
//     */
//    function _removeTokenFromOwnerEnumeration(address from, uint256 tokenId) private {
//        // To prevent a gap in from's tokens array, we store the last token in the index of the token to delete, and
//        // then delete the last slot (swap and pop).
//
//        uint256 lastTokenIndex = _ownedTokens[from].length.sub(1);
//        uint256 tokenIndex = _ownedTokensIndex[tokenId];
//
//        // When the token to delete is the last token, the swap operation is unnecessary
//        if (tokenIndex != lastTokenIndex) {
//            uint256 lastTokenId = _ownedTokens[from][lastTokenIndex];
//
//            _ownedTokens[from][tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token
//            _ownedTokensIndex[lastTokenId] = tokenIndex; // Update the moved token's index
//        }
//
//        // This also deletes the contents at the last position of the array
//        _ownedTokens[from].length--;
//
//        // Note that _ownedTokensIndex[tokenId] hasn't been cleared: it still points to the old slot (now occupied by
//        // lastTokenId, or just over the end of the array if the token was the last one).
//    }
//
//    /**
//     * @dev Private function to remove a token from this extension's token tracking data structures.
//     * This has O(1) time complexity, but alters the order of the _allTokens array.
//     * @param tokenId uint256 ID of the token to be removed from the tokens list
//     */
//    function _removeTokenFromAllTokensEnumeration(uint256 tokenId) private {
//        // To prevent a gap in the tokens array, we store the last token in the index of the token to delete, and
//        // then delete the last slot (swap and pop).
//
//        uint256 lastTokenIndex = _allTokens.length.sub(1);
//        uint256 tokenIndex = _allTokensIndex[tokenId];
//
//        // When the token to delete is the last token, the swap operation is unnecessary. However, since this occurs so
//        // rarely (when the last minted token is burnt) that we still do the swap here to avoid the gas cost of adding
//        // an 'if' statement (like in _removeTokenFromOwnerEnumeration)
//        uint256 lastTokenId = _allTokens[lastTokenIndex];
//
//        _allTokens[tokenIndex] = lastTokenId; // Move the last token to the slot of the to-delete token
//        _allTokensIndex[lastTokenId] = tokenIndex; // Update the moved token's index
//
//        // This also deletes the contents at the last position of the array
//        _allTokens.length--;
//        _allTokensIndex[tokenId] = 0;
//    }
//}
//
//contract TRC721TatumToken is TRC721, TRC721Enumerable, TRC721MetadataMintable {
//
//    // mapping cashback to addresses and their values
//    mapping(uint256 => address[]) private _cashbackRecipients;
//    mapping(uint256 => uint256[]) private _cashbackValues;
//
//    constructor(string memory name, string memory symbol) public TRC721Metadata(name, symbol) {
//
//    }
//    
//    function burn(uint256 tokenId) public {
//        return super._burn(_msgSender(), tokenId);
//    }
//
//    function tokenCashbackValues(uint256 tokenId)
//    public view returns (uint256[] memory)
//    {
//        return _cashbackValues[tokenId];
//    }
//
//    function tokenCashbackRecipients(uint256 tokenId)
//    public view returns (address[] memory)
//    {
//        return _cashbackRecipients[tokenId];
//    }
//
//    function mintMultiple(
//        address[] memory to,
//        uint256[] memory tokenId,
//        string[] memory uri
//    ) public onlyMinter returns (bool) {
//        for (uint256 i = 0; i < to.length; i++) {
//            _mint(to[i], tokenId[i]);
//            _setTokenURI(tokenId[i], uri[i]);
//        }
//        return true;
//    }
//
//    function updateCashbackForAuthor(
//        uint256 tokenId,
//        uint256 cashbackValue
//    ) public returns (bool) {
//        for (uint256 i = 0; i < _cashbackValues[tokenId].length; i++) {
//            if (_cashbackRecipients[tokenId][i] == _msgSender()) {
//                _cashbackValues[tokenId][i] = cashbackValue;
//                return true;
//            }
//        }
//        return true;
//    }
//
//
//    function mintWithCashback(
//        address to,
//        uint256 tokenId,
//        string memory uri,
//        address[] memory recipientAddresses,
//        uint256[] memory cashbackValues
//    ) public onlyMinter returns (bool) {
//        _mint(to, tokenId);
//        _setTokenURI(tokenId, uri);
//        // saving cashback addresses and values
//        _cashbackRecipients[tokenId] = recipientAddresses;
//        _cashbackValues[tokenId] = cashbackValues;
//        return true;
//    }
//
//    function tokensOfOwner(address owner) public view returns (uint256[] memory) {
//        return super._tokensOfOwner(owner);
//    }
//
//    function safeTransfer(address to, uint256 tokenId) public payable {
//        if (_cashbackRecipients[tokenId].length != 0) {
//            // checking cashback addresses exists and sum of cashbacks
//            require(
//                _cashbackRecipients[tokenId].length != 0,
//                "CashbackToken should be of cashback type"
//            );
//            uint256 sum = 0;
//            for (uint256 i = 0; i < _cashbackValues[tokenId].length; i++) {
//                sum += _cashbackValues[tokenId][i];
//            }
//            if (sum > msg.value) {
//                msg.sender.transfer(msg.value);
//                revert("Value should be greater than or equal to cashback value");
//            }
//            for (uint256 i = 0; i < _cashbackRecipients[tokenId].length; i++) {
//                // transferring cashback to authors
//                if (_cashbackValues[tokenId][i] > 0) {
//                    address(uint160(_cashbackRecipients[tokenId][i])).transfer(
//                        _cashbackValues[tokenId][i]
//                    );
//                }
//            }
//            if (msg.value > sum) {
//                msg.sender.transfer(msg.value - sum);
//            }
//            _safeTransferFrom(_msgSender(), to, tokenId, "");
//        } else {
//            if (msg.value > 0) {
//                msg.sender.transfer(msg.value);
//            }
//            _safeTransferFrom(_msgSender(), to, tokenId, "");
//        }
//    }
//
//}
