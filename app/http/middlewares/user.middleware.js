const cookieParser = require("cookie-parser");
const createHttpError = require("http-errors");
const JWT = require("jsonwebtoken");
const { UserModel } = require("../../models/user");

async function verifyAccessToken(req, res, next) {
  try {
    console.log("🔐 req.secure:", req.secure);
    console.log("🍪 signedCookies:", req.signedCookies);
    console.log("🍪 cookies:", req.cookies); // برای مقایسه
    const token = req.signedCookies["accessToken"];
    if (!token) {
      throw createHttpError.Unauthorized(
        "لطفا وارد حساب کاربری خود شوید."
      );
    }
    JWT.verify(
      token,
      process.env.ACCESS_TOKEN_SECRET_KEY,
      async (err, payload) => {
        try {
          if (err)
            throw createHttpError.Unauthorized("توکن نامعتبر است");
          const { _id } = payload;
          const user = await UserModel.findById(_id, {
            password: 0,
            otp: 0,
          });
          if (!user)
            throw createHttpError.Unauthorized(
              "حساب کاربری یافت نشد"
            );
          req.user = user;
          return next();
        } catch (error) {
          next(error);
        }
      }
    );
  } catch (error) {
    next(error);
  }
}

async function isVerifiedUser(req, res, next) {
  try {
    const user = req.user;
    if (user.status === 1) {
      throw createHttpError.Forbidden(
        "پروفایل شما در انتظار بررسی است."
      );
    }
    if (user.status !== 2) {
      throw createHttpError.Forbidden(
        "پروفایل شما مورد تایید قرار نگرفته است."
      );
    }
    return next();
  } catch (error) {
    next(error);
  }
}

function decideAuthMiddleware(req, res, next) {
  const accessToken = req.signedCookies["accessToken"];
  if (accessToken) {
    return verifyAccessToken(req, res, next);
  }
  // skip this middleware
  next();
}

module.exports = {
  verifyAccessToken,
  decideAuthMiddleware,
  isVerifiedUser,
};
