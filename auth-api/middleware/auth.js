const jwt = require("jsonwebtoken");
const {SECRET_KEY} = require("../config");
const ExpressError = require("../expressError");

function authenticateJWT(req, res, next){
  try {
    const payload = jwt.verify(req.body._token, SECRET_KEY);
    req.user = payload;
    console.log("You have a valid token!");
    return next();
  } catch (err) {
    return next(err);
  }
}

function ensureLoggedIn(req, res, next){
  try {
    if (!req.user){
      throw new ExpressError("Unauthorized", 401);
    }else{
      return next();
    }
  } catch (err) {
    return next(err);
  }
}

module.exports = {authenticateJWT, ensureLoggedIn};