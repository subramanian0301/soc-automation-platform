const { PrismaClient } = require('../backend/node_modules/@prisma/client');
const prisma = new PrismaClient();

async function run() {
  try {
    const analyses = await prisma.analysis.findMany({
      orderBy: { uploadedAt: 'desc' },
      take: 20,
      select: {
        id: true,
        analysisId: true,
        fileName: true,
        originalFileName: true,
        uploadedAt: true,
        riskScore: true,
        threatLevel: true,
        status: true,
        parsingStatus: true,
        fileType: true,
      },
    });
    console.log(JSON.stringify(analyses, null, 2));
  } catch (err) {
    console.error('Error querying analyses:', err);
  } finally {
    await prisma.$disconnect();
  }
}

run();
