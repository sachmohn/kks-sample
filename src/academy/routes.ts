import { Router, Request, Response } from 'express';
import { authenticateToken, requireRole } from '../auth/middleware';
import { Role } from '../auth/types';
import { mockStudents, mockClasses, BELT_PROGRESSION } from './data';

export const academyRouter = Router();

// Student roster (available to authenticated users)
academyRouter.get('/students', authenticateToken, (_req: Request, res: Response) => {
  res.status(200).json({
    students: mockStudents,
    beltLevels: BELT_PROGRESSION,
  });
});

// Class schedules
academyRouter.get('/classes', authenticateToken, (_req: Request, res: Response) => {
  res.status(200).json({
    classes: mockClasses,
  });
});

// Academy Stats (Master / Instructor overview)
academyRouter.get(
  '/stats',
  authenticateToken,
  requireRole([Role.MASTER, Role.INSTRUCTOR]),
  (_req: Request, res: Response) => {
    const totalStudents = mockStudents.length + 140; // baseline demo count
    const eligibleCount = mockStudents.filter((s) => s.eligibleForGrading).length + 22;
    res.status(200).json({
      totalStudents,
      activeInstructors: 6,
      classesPerWeek: 18,
      eligibleForGrading: eligibleCount,
      dojoCapacityPercent: 88,
      upcomingGradingDate: '2026-12-15',
    });
  }
);

// Student Promotion (Instructors or Masters can promote a student)
academyRouter.post(
  '/promote',
  authenticateToken,
  requireRole([Role.MASTER, Role.INSTRUCTOR]),
  (req: Request, res: Response) => {
    const { studentId } = req.body;
    const student = mockStudents.find((s) => s.studentId === studentId || s.id === studentId);

    if (!student) {
      return res.status(404).json({ error: 'Student not found in dojo roster' });
    }

    const currentIndex = BELT_PROGRESSION.findIndex((b) => b.name === student.currentBelt);
    if (currentIndex < BELT_PROGRESSION.length - 1) {
      const nextBelt = BELT_PROGRESSION[currentIndex + 1];
      student.currentBelt = nextBelt.name;
      student.beltColor = nextBelt.color;
      student.kyuRank = nextBelt.kyu;
      student.katasMastered.push(`Advanced Kata ${student.kyuRank}`);
      student.eligibleForGrading = false;

      return res.status(200).json({
        message: `🥋 Congratulations! ${student.name} promoted to ${nextBelt.name} (${nextBelt.kyu})!`,
        student,
      });
    }

    return res.status(400).json({
      message: `${student.name} has already attained the highest Dan rank in current curriculum.`,
      student,
    });
  }
);

// Mark Attendance
academyRouter.post(
  '/attendance',
  authenticateToken,
  requireRole([Role.MASTER, Role.INSTRUCTOR]),
  (req: Request, res: Response) => {
    const { studentId, status } = req.body;
    const student = mockStudents.find((s) => s.studentId === studentId || s.id === studentId);

    if (!student) {
      return res.status(404).json({ error: 'Student not found' });
    }

    if (status === 'present') {
      student.totalClasses += 1;
      student.attendancePercent = Math.min(100, student.attendancePercent + 1);
    }

    return res.status(200).json({
      message: `Attendance recorded for ${student.name}: ${status.toUpperCase()}`,
      student,
    });
  }
);

// My Profile Endpoint
academyRouter.get('/my-profile', authenticateToken, (req: Request, res: Response) => {
  const userId = req.user?.sub;
  const role = req.user?.role;

  if (role === Role.STUDENT) {
    const student = mockStudents.find((s) => s.id === userId) || mockStudents[0];
    return res.status(200).json({
      role: Role.STUDENT,
      profile: student,
      classes: mockClasses.slice(0, 2),
    });
  }

  return res.status(200).json({
    role,
    profile: {
      name: req.user?.username || 'Sensei',
      role,
      dojoLocation: 'Central Honbu Dojo - Hall A',
      rank: role === Role.MASTER ? '8th Dan Black Belt (Hanshi)' : '4th Dan Black Belt (Renshi)',
    },
    students: mockStudents,
    classes: mockClasses,
  });
});
