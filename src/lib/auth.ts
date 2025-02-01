import NextAuth from "next-auth"
import Credentials from "next-auth/providers/credentials"
import GitHub from "next-auth/providers/github"
import { prisma } from "./prisma"
import { PrismaAdapter } from "@auth/prisma-adapter"

const adapter = PrismaAdapter(prisma)
 
export const { handlers, signIn, signOut, auth } = NextAuth({
  adapter,
  providers: [GitHub, Credentials({
    credentials: {
      email: { type: "email" },
      password: { type: "password" },
    },
    authorize: async (credentials) => {
      const user = await prisma.user.findFirst({
        where: { email: credentials.email, password: credentials.password },
      })

      if(!user) {
        return null
      }
      return user;
    }
  })],
})