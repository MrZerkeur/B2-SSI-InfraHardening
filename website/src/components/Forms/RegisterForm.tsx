"use client"

import { register } from "@/app/actions";
import { useFormState } from "react-dom";

export default function RegisterForm() {

  const [state, formAction] = useFormState<any, FormData>(register, undefined)

  return (
    <form action={formAction} className="flex flex-col justify-center items-center gap-2 w-1/2 h-36 bg-gray-900 rounded-md">
      <input className="rounded-sm" type="text" name="username" required placeholder="Enter username" />
      <input className="rounded-sm" type="password" name="password1" required placeholder="Enter password" />
      <input className="rounded-sm" type="password" name="password2" required placeholder="Confirm password" />
      <button className="text-white">Register</button>
      {state?.error && <p className="text-red-500">{state.error} !</p>}
    </form>
  )
}