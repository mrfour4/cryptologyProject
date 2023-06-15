const express = require("express");
const router = express.Router();
const usersController = require("../../controllers/usersController");
const ROLES_LIST = require("../../config/roles_list");
const verifyRoles = require("../../middleware/verifyRoles");
const verifySignature = require("../../middleware/verifySignature");

router
    .route("/")
    .get(verifyRoles(ROLES_LIST.Admin), usersController.getAllUsers)
    .delete(
        [verifyRoles(ROLES_LIST.Admin), verifySignature()],
        usersController.deleteUser
    );

router
    .route("/:id")
    .get(verifyRoles(ROLES_LIST.Admin), usersController.getUser);

module.exports = router;
