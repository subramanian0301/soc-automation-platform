const { PrismaClient } = require('@prisma/client');
const p = new PrismaClient();

async function main() {
  const a = await p.analysis.findFirst({
    where: { originalFileName: { contains: 'soc_sample_security' } },
    include: { iocs: true, siemEvents: true }
  });
  console.log('AnalysisId:', a?.analysisId);
  console.log('OriginalFileName:', a?.originalFileName);
  console.log('IOC count in DB:', a?.iocs.length);
  console.log('SIEM count in DB:', a?.siemEvents.length);
  console.log('ParsingStatus:', a?.parsingStatus);
  console.log('ParsingWarnings:', a?.parsingWarnings);
  console.log('Provenance:', a?.provenance);
}

main().catch(console.error).finally(() => p.$disconnect());
