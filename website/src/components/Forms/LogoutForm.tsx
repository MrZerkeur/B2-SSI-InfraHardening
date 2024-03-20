import { logout } from "@/app/actions";

export default function LogoutForm() {
  return (
    <form action={logout}>
      <button className="text-white">Logout</button>
    </form>
  )
}
