export interface StudentRecord {
  id: string;
  studentId: string;
  name: string;
  currentBelt: string;
  beltColor: string;
  kyuRank: string;
  attendancePercent: number;
  totalClasses: number;
  katasMastered: string[];
  eligibleForGrading: boolean;
  nextGradingDate: string;
  instructorNotes: string;
}

export interface ClassSchedule {
  id: string;
  title: string;
  batch: string;
  time: string;
  instructor: string;
  attendeesCount: number;
}

export const BELT_PROGRESSION = [
  { name: 'White Belt', color: '#e2e8f0', kyu: '10th Kyu' },
  { name: 'Yellow Belt', color: '#facc15', kyu: '8th Kyu' },
  { name: 'Orange Belt', color: '#fb923c', kyu: '7th Kyu' },
  { name: 'Green Belt', color: '#4ade80', kyu: '6th Kyu' },
  { name: 'Blue Belt', color: '#60a5fa', kyu: '4th Kyu' },
  { name: 'Purple Belt', color: '#c084fc', kyu: '3rd Kyu' },
  { name: 'Brown Belt', color: '#a16207', kyu: '1st Kyu' },
  { name: 'Black Belt (1st Dan)', color: '#1e293b', kyu: '1st Dan' },
];

export const mockStudents: StudentRecord[] = [
  {
    id: 'student-001',
    studentId: 'STUDENT-001',
    name: 'Karate Student (Demo)',
    currentBelt: 'Green Belt',
    beltColor: '#4ade80',
    kyuRank: '6th Kyu',
    attendancePercent: 92,
    totalClasses: 48,
    katasMastered: ['Heian Shodan', 'Heian Nidan', 'Heian Sandan'],
    eligibleForGrading: true,
    nextGradingDate: '2026-12-15',
    instructorNotes: 'Excellent form on roundhouse kicks and good stance stability.',
  },
  {
    id: 'student-002',
    studentId: 'STUDENT-002',
    name: 'Amina Tariq',
    currentBelt: 'Yellow Belt',
    beltColor: '#facc15',
    kyuRank: '8th Kyu',
    attendancePercent: 88,
    totalClasses: 26,
    katasMastered: ['Taikyoku Shodan', 'Heian Shodan'],
    eligibleForGrading: true,
    nextGradingDate: '2026-12-15',
    instructorNotes: 'Consistent attendance. Work on hip rotation during reverse punches.',
  },
  {
    id: 'student-003',
    studentId: 'STUDENT-003',
    name: 'Rahul Sharma',
    currentBelt: 'Brown Belt',
    beltColor: '#a16207',
    kyuRank: '1st Kyu',
    attendancePercent: 96,
    totalClasses: 114,
    katasMastered: ['Heian 1-5', 'Tekki Shodan', 'Bassai Dai', 'Kanku Dai'],
    eligibleForGrading: true,
    nextGradingDate: '2026-12-20',
    instructorNotes: 'Shodan (Black Belt) candidate. Ready for black belt technical evaluation.',
  },
  {
    id: 'student-004',
    studentId: 'STUDENT-004',
    name: 'Zaid Khan',
    currentBelt: 'White Belt',
    beltColor: '#e2e8f0',
    kyuRank: '10th Kyu',
    attendancePercent: 78,
    totalClasses: 12,
    katasMastered: ['Taikyoku Shodan'],
    eligibleForGrading: false,
    nextGradingDate: '2027-01-10',
    instructorNotes: 'Good spirit and energy. Needs 6 more classes for yellow belt exam.',
  },
  {
    id: 'student-005',
    studentId: 'STUDENT-005',
    name: 'Sara Chen',
    currentBelt: 'Blue Belt',
    beltColor: '#60a5fa',
    kyuRank: '4th Kyu',
    attendancePercent: 94,
    totalClasses: 72,
    katasMastered: ['Heian 1-4', 'Jion'],
    eligibleForGrading: true,
    nextGradingDate: '2026-12-15',
    instructorNotes: 'Outstanding kumite sparring control and balance.',
  },
];

export const mockClasses: ClassSchedule[] = [
  {
    id: 'cls-1',
    title: 'Beginners & White Belts (Basics & Kata)',
    batch: 'Morning Tigers',
    time: 'Mon / Wed / Fri — 07:00 AM',
    instructor: 'Sensei Tariq (INSTRUCTOR-001)',
    attendeesCount: 18,
  },
  {
    id: 'cls-2',
    title: 'Intermediate Katas (Heian Series & Kumite)',
    batch: 'Evening Dragons',
    time: 'Tue / Thu / Sat — 05:30 PM',
    instructor: 'Sensei Tariq (INSTRUCTOR-001)',
    attendeesCount: 24,
  },
  {
    id: 'cls-3',
    title: 'Advanced & Black Belt Candidates (Bunkai & Sparring)',
    batch: 'Elite Warriors',
    time: 'Tue / Thu / Sat — 07:00 PM',
    instructor: 'Grandmaster Khan (MASTER-001)',
    attendeesCount: 12,
  },
];
