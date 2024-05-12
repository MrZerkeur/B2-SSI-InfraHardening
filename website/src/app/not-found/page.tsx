import Link from 'next/link';

export default function NotFoundPage() {
    return (
        <div>
            <h1>404 - Page Not Found</h1>
            <p>The page you are looking for does not exist.</p>
            <Link href="/">Go back to the home page</Link>
        </div>
    );
}