import { executeAction } from "../executeAction";
import { prisma } from "../prisma";
import { userSchema } from "./schemas/userSchema";

const signUp = async (formData: FormData) => {
  return executeAction({
    actionFn: async () => {
      const email = formData.get("email");
      const password = formData.get("password");
      const validatedData = userSchema.parse({ email, password });

      await prisma.user.create({
        data: {
          email: validatedData.email,
          password: validatedData.password,
        },
      });
    }
  });
}

export { signUp };