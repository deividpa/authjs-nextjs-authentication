import NextAuth from "next-auth"
import Credentials from "next-auth/providers/credentials"
import GitHub from "next-auth/providers/github"
import { v4 as uuid } from "uuid"
import { prisma } from "./prisma"
import { PrismaAdapter } from "@auth/prisma-adapter"
import { userSchema } from "./db/schemas/userSchema"
import { encode } from "next-auth/jwt"

const adapter = PrismaAdapter(prisma)
 
export const { handlers, signIn, signOut, auth } = NextAuth({
  adapter,
  providers: [
    GitHub, 
    Credentials({
      credentials: {
        email: { type: "email" },
        password: { type: "password" },
      },
      authorize: async (credentials) => {

        const validatedCredentials = await userSchema.parse(credentials)

        const user = await prisma.user.findFirst({
          where: { email: validatedCredentials.email, password: validatedCredentials.password },
        })

        if(!user) {
          throw new Error("Invalid credentials");
        }

        return user;
      }
    })],
  callbacks: {
    async jwt({token, account}) {
      if(account?.provider === "credentials") {
        token.credentials = true;
      }
      return token;
    }
  },
  jwt: {
    encode: async function(params) {
      if(params.token?.credentials) {
        const sessionToken = uuid();

        if(!params.token.sub) {
          throw new Error("No userId found in token");
        }

        const createdSession = await adapter?.createSession?.({
          sessionToken,
          userId: params.token.sub,
          expires: new Date(Date.now() + 30 * 24 * 60 * 60 * 1000),
        })

        if(!createdSession) {
          throw new Error("Session creation failed");
        }

        return sessionToken;
      }
    
      return encode(params);
    },
  },
})