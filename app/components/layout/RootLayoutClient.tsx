'use client';

import { usePathname } from 'next/navigation';
import AuthLayout from './AuthLayout';

interface RootLayoutClientProps {
  children: React.ReactNode;
  publicPaths: string[];
}

export default function RootLayoutClient({ children, publicPaths }: RootLayoutClientProps) {
  const pathname = usePathname();
  const isPublicPath = publicPaths.includes(pathname);

  return isPublicPath ? children : <AuthLayout>{children}</AuthLayout>;
}