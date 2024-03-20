import { redirect } from "next/navigation";
import { getSession } from "../actions";

export default async function Admin() {
  const session = await getSession();

  if (!session.isLoggedIn || !session.isAdmin) {
    redirect('/not-found');
  }
  
  return (
    <>
      <main className="flex min-h-screen flex-col items-center justify-between p-4">
        <h1 className='text-5xl'>Bien joué tu es chez l&#39;admin</h1>
      </main>
    </>
    
  )
}
