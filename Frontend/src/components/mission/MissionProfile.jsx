function MissionProfile() {
  return (
    <div className="min-h-screen bg-[#070b12] text-white p-6">
      
      {/* Page Header */}
      <div className="mb-8">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-[0.25em] text-cyan-400">
              Orbital Shield / Mission Control
            </p>

            <h1 className="mt-2 text-3xl font-semibold tracking-tight">
              Mission Profile
            </h1>

            <p className="mt-2 text-sm text-slate-400">
              Mission configuration, operational parameters and security policy
            </p>
          </div>

          <div className="flex items-center gap-3 rounded-full border border-emerald-500/20 bg-emerald-500/5 px-4 py-2">
            <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_10px_rgba(52,211,153,0.8)]" />
            <span className="text-xs font-medium tracking-wide text-emerald-400">
              MISSION ACTIVE
            </span>
          </div>
        </div>
      </div>

      {/* Mission Identity */}
      <div className="rounded-2xl border border-white/10 bg-[#0b111b] p-6 shadow-xl shadow-black/20">
        
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs uppercase tracking-widest text-slate-500">
              Satellite
            </p>

            <h2 className="mt-1 text-2xl font-semibold">
              SAT-EO-01
            </h2>

            <p className="mt-1 text-sm text-slate-400">
              Earth Observation Mission
            </p>
          </div>

          <div className="rounded-lg border border-cyan-400/20 bg-cyan-400/5 px-4 py-3 text-right">
            <p className="text-[10px] uppercase tracking-widest text-slate-500">
              Mission Type
            </p>

            <p className="mt-1 text-sm font-medium text-cyan-400">
              EARTH OBSERVATION
            </p>
          </div>
        </div>
      </div>

      {/* Content Area */}
      <div className="mt-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        
        <div className="min-h-[220px] rounded-2xl border border-white/10 bg-[#0b111b] p-6">
          <p className="text-xs uppercase tracking-widest text-slate-500">
            Orbital Information
          </p>

          <div className="mt-6 flex h-32 items-center justify-center text-sm text-slate-600">
            Orbital statistics
          </div>
        </div>

        <div className="min-h-[220px] rounded-2xl border border-white/10 bg-[#0b111b] p-6">
          <p className="text-xs uppercase tracking-widest text-slate-500">
            Security Configuration
          </p>

          <div className="mt-6 flex h-32 items-center justify-center text-sm text-slate-600">
            Security configuration
          </div>
        </div>

      </div>

    </div>
  );
}

export default MissionProfile;