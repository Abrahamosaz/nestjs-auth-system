export default () => ({
  jwt: {
    secret: process.env.JWT_SECRET,
    access_secret: process.env.JWT_ACCESS_SECRET,
    refresh_secret: process.env.JWT_REFRESH_SECRET,
  },
  templateUrl: process.env.TEMPLATE_URL,
});
