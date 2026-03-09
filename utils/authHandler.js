let jwt = require('jsonwebtoken')
let userController = require("../controllers/users");

function normalizeRoleName(roleName) {
    if (!roleName) {
        return '';
    }
    let normalized = String(roleName).trim().toUpperCase();
    if (normalized === 'MODERATOR') {
        return 'MOD';
    }
    return normalized;
}

module.exports = {
    checkLogin: function (req, res, next) {
        try {
            let token;
            if (req.cookies.token) {
                token = req.cookies.token
            }
            else {
                let authorizationToken = req.headers.authorization;
                if (!authorizationToken || !authorizationToken.startsWith("Bearer ")) {
                    res.status(403).send({
                        message: "ban chua dang nhap"
                    })
                    return;
                }
                token = authorizationToken.split(' ')[1];
            }
            let result = jwt.verify(token, 'HUTECH');
            if (result.exp && result.exp > Date.now()) {
                req.userId = result.id;
                next();
            } else {
                res.status(403).send({
                    message: "ban chua dang nhap"
                })
            }
        } catch (error) {
            res.status(403).send({
                message: "ban chua dang nhap"
            })
            return;
        }
    },
    checkRole: function (...requiredRole) {
        return async function (req, res, next) {
            try {
                let userId = req.userId;
                let getUser = await userController.FindByID(userId);
                if (!getUser || !getUser.role || !getUser.role.name) {
                    res.status(403).send({
                        message: "ban khong co quyen"
                    })
                    return;
                }
                let roleName = normalizeRoleName(getUser.role.name);
                let normalizedRequiredRole = requiredRole.map(normalizeRoleName);

                if (normalizedRequiredRole.includes(roleName)) {
                    next()
                    return;
                }
                res.status(403).send({
                    message: "ban khong co quyen"
                })
            } catch (error) {
                res.status(403).send({
                    message: "ban khong co quyen"
                })
            }
        }
    }
}
