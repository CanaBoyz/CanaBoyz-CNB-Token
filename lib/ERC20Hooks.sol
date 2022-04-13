// SPDX-License-Identifier: MIT
/// @author KRogLA (https://github.com/krogla)
pragma solidity ^0.8.0;

import "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";
import "../interfaces/IHook.sol";
import "../lib/errors.sol";

error HookRevert();
error HooksEnabledNotChanged();

contract ERC20Hooks {
    using EnumerableSet for EnumerableSet.AddressSet;

    event HookAdded(address addr);
    event HookRemoved(address addr);
    event HooksEnabled(bool enabled);

    EnumerableSet.AddressSet private _hooks;
    bool private _hooksEnabled;

    modifier withoutHooks() {
        bool enabled = _hooksEnabled;
        _hooksEnabled = false;
        _;
        _hooksEnabled = enabled;
    }

    function hooksEnabled() external view returns (bool) {
        return _hooksEnabled;
    }

    function hooks() external view returns (address[] memory) {
        return _hooks.values();
    }

    function hookExists(address hook) public view returns (bool) {
        return _hooks.contains(hook);
    }

    function hookByIndex(uint256 index) external view returns (address) {
        if (index >= _hooks.length()) revert NotExists();
        return _hooks.at(index);
    }

    function _enableHooks(bool enabled) internal {
        if (_hooksEnabled == enabled) revert HooksEnabledNotChanged();
        if (_hooks.length() == 0) revert NotExists();
        _hooksEnabled = enabled;
        emit HooksEnabled(enabled);
    }

    function _addHook(address hook) internal {
        if (hook == address(0)) revert ZeroAddress();
        if (!_hooks.add(hook)) revert AlreadyExists();
        emit HookAdded(hook);
    }

    function _removeHook(address hook) internal {
        if (hook == address(0)) revert ZeroAddress();
        if (!_hooks.remove(hook)) revert NotExists();
        emit HookRemoved(hook);
    }

    function _applyHooks(
        address sender,
        address from,
        address to,
        uint256 amount
    ) internal {
        if (_hooksEnabled) {
            uint256 n = _hooks.length();
            for (uint256 i = 0; i < n; i++) {
                if (!IHook(_hooks.at(i)).assure(sender, from, to, amount)) revert HookRevert();
            }
        }
    }
}
