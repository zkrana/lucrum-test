import { NextResponse } from 'next/server';
import { getServerSession } from "next-auth";
import { authOptions } from "../auth/[...nextauth]/route";

// Define the expected structure of a document
interface DocumentItem {
  id: string;
  title: string;
  description?: string;
  fileUrl: string;
  file_type: string;
  file_size: number | null;
  category: string;
  uploaded_by?: string | null;
  is_public: number;
  downloads: number;
  created_at: string;
}

export async function GET() {
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json(
        { error: "Unauthorized access" },
        { status: 401 }
      );
    }

    console.log("📍 Fetching CPA/Legal documents...");

    const response = await fetch('http://localhost:8000/api/rest-api/cpa-legal/CpaLegalApi.php', {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${session.user.accessToken}`
      }
    });

    if (!response.ok) {
      const error = await response.json();
      throw new Error(error.message || 'Failed to fetch CPA/Legal documents');
    }

    const documents: DocumentItem[] = await response.json();

    console.log("🔍 Documents retrieved:", documents.length);

    const formattedDocuments = documents.map((doc: DocumentItem) => ({
      ...doc,
      id: String(doc.id),
      file_size: doc.file_size ? Number(doc.file_size) : null,
      downloads: doc.downloads ? Number(doc.downloads) : 0,
      created_at: new Date(doc.created_at).toISOString(),
      uploaded_by: doc.uploaded_by || null,
      category: doc.category || 'unknown',
      file_path: doc.fileUrl.startsWith('http')
        ? doc.fileUrl
        : `http://localhost:8000/public/${doc.fileUrl.replace(/^\/+/, '')}`
    }));

    return NextResponse.json(formattedDocuments);

  } catch (error: unknown) {
    console.error("❌ Error fetching CPA documents:", error);
    return NextResponse.json(
      { error: "Failed to fetch documents", details: error instanceof Error ? error.message : "Unknown error" },
      { status: 500 }
    );
  }
}