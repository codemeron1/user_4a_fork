export default {
  jwtSecret: process.env.JWT_SECRET || "your_jwt_secret",
  jwtRefreshSecret: process.env.JWT_REFRESH_SECRET || "your_refresh_secret",
  tokenExpiry: "1h",
  refreshExpiry: "7d"
};
