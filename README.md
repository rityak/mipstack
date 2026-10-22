# mipstack

Сетевой стек mips для TUN.

Форк [metacubex/mipstack](https://github.com/metacubex/mipstack) для [miray](https://github.com/rityak/miray). Наш код — в ветке `miray`.

## Что изменено

- Буфер приёма TCP подстраивается по RTT, который получатель меряет по эхо timestamps. Раньше брался RTT рукопожатия, и на отдаче через TUN буфер застревал на 1 МиБ.
- Цель буфера приёма удвоена: окно около двух RTT.
- Влиты исправления TCP из апстрима до 2026-10-19 (RACK, восстановление после потерь, RTO, ICMPv6).
