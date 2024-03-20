"use client"

import { login } from "@/app/actions";
import { useFormState } from "react-dom";

export default function LoginForm() {

  const [state, formAction] = useFormState<any, FormData>(login, undefined)

  return (
    <form action={formAction} className="flex flex-col justify-center items-center gap-2 w-1/2 h-36 bg-gray-900 rounded-md">
      <input className="rounded-sm" type="text" name="username" required placeholder="Enter username" />
      <input className="rounded-sm" type="password" name="password" required placeholder="Enter password" />
      <button className="text-white">Login</button>
      {state?.error && <p className="text-red-500">{state.error} !</p>}
    </form>
  )
}