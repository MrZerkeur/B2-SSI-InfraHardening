import { redirect } from "next/navigation";
import { getSession } from "../actions"


export default async function Profile() {
  const session = await getSession();

  if (!session.isLoggedIn) {
    redirect('/login');
  }

  return (
    <>
      <main className="flex min-h-screen flex-col items-center p-4 gap-4">
        <h1 className='text-5xl'>Profile</h1>
        <h2>Welcome <b>{session.username}</b></h2>
        <span>
          You are {session.isAdmin ? "an " : "a "}
          <b>{session.isAdmin ? "Administrator" : "User"}</b>
        </span>
      </main>
    </>
  )
}
