const { PrismaClient } = require('../backend/node_modules/@prisma/client');
const prisma = new PrismaClient();

async function run() {
  try {
    const socAnalyses = await prisma.analysis.findMany({
      where: {
        OR: [
          { originalFileName: { contains: 'soc_sample' } },
          { originalFileName: { contains: 'security' } }
        ]
      },
      orderBy: { uploadedAt: 'desc' },
      take: 10,
      include: {
        behaviorEvents: true,
        siemEvents: true,
        mitreTechniques: true,
        sandboxResults: true,
        soarExecutions: true,
        incidents: true,
        assets: true,
        endpoints: true,
        vulnerabilities: true,
        fileMetadata: true,
      }
    });

    console.log(`Found ${socAnalyses.length} analyses matching soc_sample or security:`);
    for (const a of socAnalyses) {
      console.log({
        analysisId: a.analysisId,
        fileName: a.fileName,
        originalFileName: a.originalFileName,
        uploadedAt: a.uploadedAt,
        riskScore: a.riskScore,
        threatLevel: a.threatLevel,
        parsingStatus: a.parsingStatus,
        behaviorEventsCount: a.behaviorEvents.length,
        siemEventsCount: a.siemEvents.length,
        mitreCount: a.mitreTechniques.length,
        sandboxCount: a.sandboxResults.length,
        soarCount: a.soarExecutions.length,
        incidentsCount: a.incidents.length,
        assetsCount: a.assets.length,
        endpointsCount: a.endpoints.length,
        vulnerabilitiesCount: a.vulnerabilities.length,
        behaviorEvents: a.behaviorEvents,
      });
    }
  } catch (err) {
    console.error('Error:', err);
  } finally {
    await prisma.$disconnect();
  }
}

run();
