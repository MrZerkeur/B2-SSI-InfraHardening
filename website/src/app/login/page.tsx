import LoginForm from "@/components/Forms/LoginForm"

export default function Login() {
  return (
    <>
      <main className="flex gap-4 min-h-screen flex-col items-center p-4">
        <h1 className='text-5xl'>Login</h1>
        <LoginForm/>
      </main>
    </>
  )
}
