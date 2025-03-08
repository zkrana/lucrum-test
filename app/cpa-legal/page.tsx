'use client';

import { useEffect, useState } from 'react';

interface CPADocument {
  id: string;
  title: string;
  description: string | null;
  file_path: string;
  fileUrl: string;
  file_type: string | null;
  downloads: number;
  created_at: string;
  uploaded_by: string | null;
  category: 'cpa' | 'legal';
}

export default function CPALegalPage() {
  const [documents, setDocuments] = useState<CPADocument[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedType, setSelectedType] = useState<'all' | 'cpa' | 'legal'>('all');
  const [selectedPdf, setSelectedPdf] = useState<string | null>(null);
  const [pdfError, setPdfError] = useState<string | null>(null);

  useEffect(() => {
    const fetchDocuments = async () => {
      try {
        console.log('📍 Fetching documents from:', '/api/cpa-legal');
        const response = await fetch('/api/cpa-legal');

        if (!response.ok) {
          console.error('🚨 API Response not OK:', {
            status: response.status,
            statusText: response.statusText,
          });
          throw new Error(`HTTP error! Status: ${response.status}`);
        }

        const result = await response.json();
        console.log('✅ API Response:', result);

        if (Array.isArray(result)) {
          setDocuments(result);
          console.log('📄 Processed Documents:', result);
        } else {
          throw new Error(result.error || 'Failed to fetch documents');
        }
      } catch (err: any) {
        console.error('❌ Document fetch error:', err);
        setError(err.message);
      } finally {
        setLoading(false);
      }
    };

    fetchDocuments();
  }, []);

  const handlePdfView = (doc: CPADocument) => {
    setPdfError(null);
    const pdfUrl = doc.file_path || doc.fileUrl;
    if (!pdfUrl) {
      setPdfError('PDF file path is missing');
      return;
    }
    setSelectedPdf(pdfUrl);
  };

  if (loading) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="animate-spin rounded-full h-12 w-12 border-t-2 border-b-2 border-blue-500"></div>
      </div>
    );
  }

  if (error) {
    return (
      <div className="min-h-screen flex items-center justify-center">
        <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative" role="alert">
          <strong className="font-bold">Error: </strong>
          <span className="block sm:inline">{error}</span>
        </div>
      </div>
    );
  }

  const filteredDocuments = selectedType === 'all'
    ? documents
    : documents.filter((doc) => doc.category === selectedType);

  return (
    <div className="container mx-auto">
      <div className="mb-2">
        <div className="text-left py-2">
          <h1 className="pl-2 text-[26px] uppercase font-bold bg-gradient-to-r from-[#0175E2] to-transparent text-white rounded-[10px] w-full mb-4">
            CPA/Legal Documents
          </h1>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filteredDocuments.map((doc) => (
          <div key={doc.id} className="bg-white rounded-[20px] p-2 overflow-hidden transform transition-all duration-300 hover:shadow-xl hover:-translate-y-1">
            <div className="relative rounded-t-[20px] h-48 bg-gray-50 flex items-center justify-center group">
              <div className="text-gray-400 group-hover:text-gray-500 transition-colors">
                <svg className="w-20 h-20" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                </svg>
              </div>
              <button
                onClick={() => handlePdfView(doc)}
                className="absolute inset-0 flex items-center justify-center bg-black bg-opacity-0 group-hover:bg-opacity-30 transition-all duration-300"
              >
                <div className="w-12 h-12 rounded-full bg-white shadow-lg flex items-center justify-center transform scale-0 group-hover:scale-100 transition-transform duration-300">
                  <svg className="w-6 h-6 text-blue-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 12a3 3 0 11-6 0 3 3 0 016 0z" />
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M2.458 12C3.732 7.943 7.523 5 12 5c4.478 0 8.268 2.943 9.542 7-1.274 4.057-5.064 7-9.542 7-4.477 0-8.268-2.943-9.542-7z" />
                  </svg>
                </div>
              </button>
            </div>

            <div className="p-6">
              <div className="mb-4">
                <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium capitalize ${doc.category === 'cpa' ? 'bg-blue-100 text-blue-800' : 'bg-purple-100 text-purple-800'}`}>
                  {doc.category}
                </span>
              </div>

              <h3 className="text-xl font-semibold text-[#0175E1] mb-2 line-clamp-2">{doc.title}</h3>
              <p className="text-gray-600 mb-4 line-clamp-3">{doc.description}</p>

              <div className="flex justify-between items-center pt-4 border-t border-gray-100">
                <span className="text-sm text-gray-500">{new Date(doc.created_at).toLocaleDateString()}</span>
                <span className="text-sm text-gray-500">{doc.downloads} downloads</span>
              </div>
            </div>
          </div>
        ))}
      </div>

      {selectedPdf && (
        <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4">
          <div className="bg-white rounded-lg p-4 w-full max-w-4xl max-h-[90vh] overflow-auto">
            <div className="flex justify-between items-center mb-4">
              <h2 className="text-lg font-semibold">Document Viewer</h2>
              <button
                onClick={() => {
                  setSelectedPdf(null);
                  setPdfError(null);
                }}
                className="text-gray-500 hover:text-gray-700"
              >
                Close
              </button>
            </div>
            {pdfError ? (
              <div className="bg-red-100 border border-red-400 text-red-700 px-4 py-3 rounded relative">
                <strong className="font-bold">Error: </strong>
                <span className="block sm:inline">{pdfError}</span>
              </div>
            ) : (
              <iframe
                src={selectedPdf}
                className="w-full h-[80vh]"
                title="PDF Viewer"
                onError={() => setPdfError('Failed to load PDF file')}
              />
            )}
          </div>
        </div>
      )}
    </div>
  );
}