import { VisualReportViewer } from "@/components/visual-report-viewer";

export default async function Page({ params }: { params: Promise<{ reportId: string }> }) {
  const { reportId } = await params;
  return <VisualReportViewer reportId={reportId} />;
}
