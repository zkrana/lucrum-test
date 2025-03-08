import { DefaultSession } from "next-auth";

declare module "next-auth" {
  interface Session {
    user: {
      id: string;
      hasDashboardAccess: boolean;
      isAdmin: boolean;
      status: string;
      authProvider: string;
      accessToken: string; // ✅ Add this line
    } & DefaultSession["user"];
  }
}