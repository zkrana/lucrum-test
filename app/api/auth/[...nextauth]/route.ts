import NextAuth, { NextAuthOptions } from "next-auth";
import GoogleProvider from "next-auth/providers/google";
import CredentialsProvider from "next-auth/providers/credentials";

export const authOptions: NextAuthOptions = {
  secret: process.env.NEXTAUTH_SECRET,
  debug: process.env.NODE_ENV === "development",
  session: { strategy: "jwt", maxAge: 30 * 24 * 60 * 60 }, // 30 days

  providers: [
    GoogleProvider({
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
      debug: true,
    }),
    CredentialsProvider({
      id: "credentials",
      name: "credentials",
      credentials: {
        email: { label: "Email", type: "email" },
        password: { label: "Password", type: "password" },
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          throw new Error("Missing credentials");
        }

        const response = await fetch("http://localhost:8000/api/rest-api/auth/login.php", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ email: credentials.email, password: credentials.password }),
        });

        const data = await response.json();
        if (!response.ok || !data.user || !data.token) {
          throw new Error(data.message || "Authentication failed");
        }

        if (data.user.status === "pending") {
          throw new Error("Your account is pending approval. Please contact support.");
        }

        return {
          id: data.user.id,
          email: data.user.email,
          name: data.user.name,
          status: data.user.status,
          hasDashboardAccess: data.user.hasDashboardAccess || false,
          accessToken: data.token,
        };
      },
    }),
  ],

  callbacks: {
    async signIn({ user, account, profile }) {
      if (account?.provider === "google") {
        const registerUrl = "http://localhost:8000/api/rest-api/auth/provider_register.php";
        const loginUrl = "http://localhost:8000/api/rest-api/auth/provider_login.php";

        try {
          const registerResponse = await fetch(registerUrl, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              email: user.email,
              name: user.name,
              googleId: profile.sub,
              access_token: account.access_token,
              refresh_token: account.refresh_token,
              expires_at: account.expires_at,
              id_token: account.id_token,
            }),
          });

          const registerData = await registerResponse.json();

          if (registerData.message === "Account already exists with Google login") {
            const loginResponse = await fetch(loginUrl, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({
                email: user.email,
                googleId: profile.sub,
                access_token: account.access_token,
              }),
            });

            const loginData = await loginResponse.json();

            if (!loginResponse.ok || !loginData.user || !loginData.token) {
              return false;
            }

            // ❌ Prevent login if the user is still pending
            if (loginData.user.status === "pending") {
              throw new Error("Your account is pending approval. Please contact support.");
            }

            return {
              id: loginData.user.id,
              email: loginData.user.email,
              name: loginData.user.name,
              status: loginData.user.status,
              hasDashboardAccess: loginData.user.hasDashboardAccess || false,
              accessToken: loginData.token,
            };
          }

          if (!registerResponse.ok || !registerData.user || !registerData.token) {
            return false;
          }

          return {
            id: registerData.user.id,
            email: registerData.user.email,
            name: registerData.user.name,
            status: registerData.user.status,
            hasDashboardAccess: registerData.user.hasDashboardAccess || false,
            accessToken: registerData.token,
          };
        } catch (error) {
          console.error("❌ Google SignIn Error:", error);
          return false;
        }
      }
      return true;
    },

    async jwt({ token, user }) {
      if (user) {
        token.accessToken = user.accessToken;
        token.id = user.id;
        token.email = user.email;
        token.name = user.name;
        token.status = user.status;
        token.hasDashboardAccess = user.hasDashboardAccess || false;
      }
      return token;
    },

    async session({ session, token }) {
      if (session.user) {
        session.user.id = token.id;
        session.user.email = token.email;
        session.user.name = token.name;
        session.user.status = token.status;
        session.user.hasDashboardAccess = token.hasDashboardAccess;
      }
      return session;
    },
  },

  pages: {
    signIn: "/auth/signin",
    error: "/auth/error",
  },
};

const handler = NextAuth(authOptions);
export { handler as GET, handler as POST };