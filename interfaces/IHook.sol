// SPDX-License-Identifier: MIT
/// @author KRogLA (https://github.com/krogla)
pragma solidity ^0.8.0;

error HookWrongRespond();

interface IHook {
    function assure(
        address sender,
        address from,
        address to,
        uint256 amount
    ) external returns (bool allow);

    function getBlocked(address[] memory holders) external view returns (bool[] memory blocked);
}
