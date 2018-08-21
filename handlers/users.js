var helpers = require('./helpers.js'),
    user_data = require("../data/user.js"),
    async = require('async'),
    bcrypt = require('bcrypt'),
    fs = require('fs');

exports.version = "0.1.0";


function User (user_data) {
    this.userid = user_data["userid"];
    this.email = user_data["email"];
    this.display_name = user_data["display_name"];
    this.password = user_data["password"];
    this.first_seen_date = user_data["first_seen_date"];
    this.last_modified_date = user_data["last_modified_date"];
    this.deleted = user_data["deleted"];
}

User.prototype.userid = null;
User.prototype.email = null;
User.prototype.display_name = null;
User.prototype.password = null;
User.prototype.first_seen_date = null;
User.prototype.last_modified_date = null;
User.prototype.deleted = false;
User.prototype.check_password = function (pw, callback) {
    bcrypt.compare(pw, this.password, callback);
};
User.prototype.response_obj = function () {
    return {
        userid: this.userid,
        email: this.email,
        display_name: this.display_name,
        first_seen_date: this.first_seen_date,
        last_modified_date: this.last_modified_date
    };
};



exports.register = function (req, res) {
    async.waterfall([
        function (cb) {
            var em = req.body.email;
            if (!em )
                cb(helpers.invalid_email_address());
            else if (!req.body.display_name) 
                cb(helpers.missing_data("display_name"));
            else if (!req.body.password)
                cb(helpers.missing_data("password"));
            else
                cb(null);
        },

        // register da user.
        function (cb) {
            user_data.register(
                req.body.email,
                req.body.display_name,
                req.body.password,
                cb);
        },

        // mark user as logged in
        function (user_data, cb) {
            req.session.logged_in = true;
            req.session.logged_in_display_name = req.body.display_name;
            req.session.logged_in_date = new Date();
            cb(null, user_data);
        }
    ],
    function (err, user_data) {
        if (err) {
            helpers.send_failure(res, helpers.http_code_for_error(err), err);
        } else {
            var u = new User(user_data);
            helpers.send_success(res, {user: u.response_obj() });
        }
    });
};
exports.user_by_uuid = function (userid, callback) {
    user_data.user_by_uuid(userid, (err, user_data) => {
        if (err) {
            callback(err);
        } else {
            callback(null, new User(user_data));
        }
    });
};

exports.user_by_display_name = function (req, res) {
    async.waterfall([
        function (cb) {
            user_data.user_by_display_name(req.body.display_name, cb);
        }
    ],
    function (err, u) {
        if (!err) {
            helpers.send_success(res, { user: u.response_obj() });
        } else {
            helpers.send_failure(res, helpers.http_code_for_error(err), err);
        }
    });
};


exports.authenticate_user = function (un, pw, callback) {
    var user_object;
    async.waterfall([
        function (cb) {
            user_data.user_by_display_name(un, cb);
        },

        function (user_data, cb) {
            user_object = new User(user_data);
            user_object.check_password(pw, cb);
        }
    ],
    function (err, auth_ok) {
        if (!err) {
            if (auth_ok) {
                callback(null, user_object);
            } else {
                callback(helpers.error("invalid_credentials", "The given username/password are invalid."));
            }
        } else {
            callback(err);
        }
    });
};


exports.login = function (req, res) {

    async.waterfall([
        function (cb) {
     var em = req.body.email
        ? req.body.email.trim().toLowerCase()
        : "";    
            if (!em)
                cb(helpers.missing_data("email"));
            else if (req.session
                     && req.session.logged_in_email_address == em)
                cb(helpers.error("already_logged_in", ""));
            else if (!req.body.password)
                cb(helpers.missing_data("password"));
            else
            user_data.user_by_email(em, cb);
        },
        // check the password
        function (user_data, cb) {
            var u = new User(user_data);
            u.check_password(req.body.password, cb);
        },

        function (auth_ok, cb) {
            if (!auth_ok) {
                cb(helpers.auth_failed());
                return;
            }

            req.session.logged_in = true;
            req.session.logged_in_email_address = req.body.email;
            req.session.logged_in_date = new Date();
            cb(null);
        }
    ],
    function (err, results) {
        if (!err || err.message == "already_logged_in") {
            helpers.send_success(res, { logged_in: true });
        } else {
            helpers.send_failure(res, helpers.http_code_for_error(err), err);
        }
    });
};




exports.authenticate_API = function (un, pw, callback) {
    async.waterfall([
        function (cb) {
            user_data.user_by_email(un, cb);
        },

        function (user_data, cb) {
            var u = new User(user_data);
            u.check_password(pw, cb);
        }
    ],
    function (err, results) {
        if (!err) {
            callback(null, un);
        } else {
            callback(new Error("bogus credentials"));
        }
    });
};

